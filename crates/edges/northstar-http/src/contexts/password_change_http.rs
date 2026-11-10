//! Password-change HTTP authority excluding post-commit account teardown.

use crate::repositories::HttpRepositories;
use northstar_auth_application::password_change::PasswordChangeService;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[derive(Clone)]
pub struct PasswordChangeHttpContext<R: HttpRepositories> {
    pub service: PasswordChangeService<R::PasswordChange>,
    pub trusted_proxies: Vec<IpAddr>,
    pub domain: String,
    pub rate_limited: Arc<AtomicU64>,
    pub backend_failures: Arc<AtomicU64>,
}

impl<R: HttpRepositories> PasswordChangeHttpContext<R> {
    pub fn service(&self) -> &PasswordChangeService<R::PasswordChange> {
        &self.service
    }

    pub fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn abuse_denied(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn backend_unavailable(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }
}
