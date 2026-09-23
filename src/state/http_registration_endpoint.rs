//! REST registration capability: account admission, proxy policy and outcome counters.

use super::AppState;
use crate::{
    db::account_repository::PostgresAccountRepository,
    services::account::{AccountService, HttpRegistrationAvailability},
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
pub(crate) struct HttpRegistrationEndpointContext {
    service: AccountService<PostgresAccountRepository>,
    availability: HttpRegistrationAvailability,
    trusted_proxies: Vec<IpAddr>,
    registrations: Arc<AtomicU64>,
    rate_limited: Arc<AtomicU64>,
    capacity_rejected: Arc<AtomicU64>,
}

impl FromRef<Arc<AppState>> for HttpRegistrationEndpointContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: state.account_service.clone(),
            availability: state.http_registration_availability(),
            trusted_proxies: state.config.trusted_proxy_ips.clone(),
            registrations: Arc::clone(&state.metrics.registrations_total),
            rate_limited: Arc::clone(&state.metrics.rate_limited_total),
            capacity_rejected: Arc::clone(&state.metrics.capacity_reservations_rejected_total),
        }
    }
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
