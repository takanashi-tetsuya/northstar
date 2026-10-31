//! REST registration capability: account admission, proxy policy and outcome counters.

use crate::db::account_repository::PostgresAccountRepository;
use northstar_auth_application::account::{AccountService, HttpRegistrationAvailability};
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[derive(Clone)]
pub(crate) struct HttpRegistrationEndpointContext {
    pub(crate) service: AccountService<PostgresAccountRepository>,
    pub(crate) availability: HttpRegistrationAvailability,
    pub(crate) trusted_proxies: Vec<IpAddr>,
    pub(crate) registrations: Arc<AtomicU64>,
    pub(crate) rate_limited: Arc<AtomicU64>,
    pub(crate) capacity_rejected: Arc<AtomicU64>,
}

impl HttpRegistrationEndpointContext {
    pub(crate) fn service(&self) -> &AccountService<PostgresAccountRepository> {
        &self.service
    }

    pub(crate) fn availability(&self) -> HttpRegistrationAvailability {
        self.availability.clone()
    }

    pub(crate) fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub(crate) fn created(&self) {
        self.registrations.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn abuse_denied(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn capacity_exhausted(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
    }
}
