//! REST login transport capability: credential use case, immutable proxy
//! policy, and only the two counters this endpoint can increment.

use crate::repositories::HttpRepositories;
use northstar_auth_application::http_login::HttpLoginService;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct HttpLoginEndpointContext<R: HttpRepositories> {
    pub service: HttpLoginService<R::HttpLogin>,
    pub trusted_proxies: Vec<IpAddr>,
    pub counters: HttpLoginEndpointCounters,
}

#[derive(Clone)]
pub struct HttpLoginEndpointCounters {
    pub rate_limited: Arc<AtomicU64>,
    pub backend_failures: Arc<AtomicU64>,
}

impl HttpLoginEndpointCounters {
    fn abuse_denied(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    fn backend_unavailable(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }
}

impl<R: HttpRepositories> HttpLoginEndpointContext<R> {
    pub fn service(&self) -> &HttpLoginService<R::HttpLogin> {
        &self.service
    }

    pub fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub fn abuse_denied(&self) {
        self.counters.abuse_denied();
    }

    pub fn backend_unavailable(&self) {
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
