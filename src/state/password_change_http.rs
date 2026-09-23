//! Password-change HTTP authority excluding post-commit account teardown.

use super::AppState;
use crate::{
    db::password_change_repository::PostgresPasswordChangeRepository,
    services::password_change::PasswordChangeService,
};
use axum::extract::FromRef;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[derive(Clone)]
pub(crate) struct PasswordChangeHttpContext {
    service: PasswordChangeService<PostgresPasswordChangeRepository>,
    trusted_proxies: Vec<IpAddr>,
    domain: String,
    rate_limited: Arc<AtomicU64>,
    backend_failures: Arc<AtomicU64>,
}

impl FromRef<Arc<AppState>> for PasswordChangeHttpContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: state.password_change_service.clone(),
            trusted_proxies: state.config.trusted_proxy_ips.clone(),
            domain: state.local_domain().to_owned(),
            rate_limited: Arc::clone(&state.metrics.rate_limited_total),
            backend_failures: Arc::clone(&state.metrics.authentication_backend_failures_total),
        }
    }
}

impl PasswordChangeHttpContext {
    pub(crate) fn service(&self) -> &PasswordChangeService<PostgresPasswordChangeRepository> {
        &self.service
    }

    pub(crate) fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    pub(crate) fn abuse_denied(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn backend_unavailable(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }
}
