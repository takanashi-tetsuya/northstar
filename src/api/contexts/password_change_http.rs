//! Password-change HTTP authority excluding post-commit account teardown.

use crate::api::postgres_repositories::PostgresHttpRepositories;
use crate::api::repositories::HttpRepositories;
use northstar_auth_application::password_change::PasswordChangeService;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[derive(Clone)]
pub(crate) struct PasswordChangeHttpContext<R: HttpRepositories = PostgresHttpRepositories> {
    pub(crate) service: PasswordChangeService<R::PasswordChange>,
    pub(crate) trusted_proxies: Vec<IpAddr>,
    pub(crate) domain: String,
    pub(crate) rate_limited: Arc<AtomicU64>,
    pub(crate) backend_failures: Arc<AtomicU64>,
}

impl<R: HttpRepositories> PasswordChangeHttpContext<R> {
    pub(crate) fn service(&self) -> &PasswordChangeService<R::PasswordChange> {
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
