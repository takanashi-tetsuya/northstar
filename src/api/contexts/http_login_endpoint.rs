//! REST login transport capability: credential use case, immutable proxy
//! policy, and only the two counters this endpoint can increment.

use crate::db::http_login_repository::PostgresHttpLoginRepository;
use northstar_auth_application::http_login::HttpLoginService;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct HttpLoginEndpointContext {
    pub(crate) service: HttpLoginService<PostgresHttpLoginRepository>,
    pub(crate) trusted_proxies: Vec<IpAddr>,
    pub(crate) counters: HttpLoginEndpointCounters,
}

#[derive(Clone)]
pub(crate) struct HttpLoginEndpointCounters {
    pub(crate) rate_limited: Arc<AtomicU64>,
    pub(crate) backend_failures: Arc<AtomicU64>,
}

impl HttpLoginEndpointCounters {
    fn abuse_denied(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    fn backend_unavailable(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }
}

impl HttpLoginEndpointContext {
    pub(crate) fn service(&self) -> &HttpLoginService<PostgresHttpLoginRepository> {
        &self.service
    }

    pub(crate) fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub(crate) fn abuse_denied(&self) {
        self.counters.abuse_denied();
    }

    pub(crate) fn backend_unavailable(&self) {
        self.counters.backend_unavailable();
    }
}

#[cfg(test)]
mod tests {
    use super::HttpLoginEndpointCounters;
    use northstar_telemetry::metrics::Metrics;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    #[test]
    fn login_outcome_counters_update_the_rendered_registry_without_other_metrics() {
        let metrics = Arc::new(Metrics::default());
        let counters = HttpLoginEndpointCounters {
            rate_limited: Arc::clone(&metrics.rate_limited_total),
            backend_failures: Arc::clone(&metrics.authentication_backend_failures_total),
        };
        counters.abuse_denied();
        assert_eq!(metrics.rate_limited_total.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics
                .authentication_backend_failures_total
                .load(Ordering::Relaxed),
            0
        );
        counters.backend_unavailable();
        let rendered = metrics.render();
        assert!(rendered.contains("xmpp_rate_limited_total 1\n"));
        assert!(rendered.contains("xmpp_authentication_backend_failures_total 1\n"));
        assert!(rendered.contains("xmpp_authentication_failures_total 0\n"));
    }
}
