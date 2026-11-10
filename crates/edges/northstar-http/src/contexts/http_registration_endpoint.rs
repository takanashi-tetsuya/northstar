//! REST registration capability: account admission, proxy policy and outcome counters.

use crate::repositories::HttpRepositories;
use northstar_auth_application::account::{AccountService, HttpRegistrationAvailability};
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[derive(Clone)]
pub struct HttpRegistrationEndpointContext<R: HttpRepositories> {
    pub service: AccountService<R::Accounts>,
    pub availability: HttpRegistrationAvailability,
    pub trusted_proxies: Vec<IpAddr>,
    pub registrations: Arc<AtomicU64>,
    pub rate_limited: Arc<AtomicU64>,
    pub capacity_rejected: Arc<AtomicU64>,
}

impl<R: HttpRepositories> HttpRegistrationEndpointContext<R> {
    pub fn service(&self) -> &AccountService<R::Accounts> {
        &self.service
    }

    pub fn availability(&self) -> HttpRegistrationAvailability {
        self.availability.clone()
    }

    pub fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub fn created(&self) {
        self.registrations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn abuse_denied(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn capacity_exhausted(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
    }
}
