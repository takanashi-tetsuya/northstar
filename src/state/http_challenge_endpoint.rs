//! Public proof-of-work issuance; bearer lookup remains with the API query context.

use super::AppState;
use crate::{
    abuse::PowChallenge,
    db::challenge_issuance_repository::PostgresChallengeRepository,
    services::challenge_issuance::{ChallengeIssueRequest, ChallengeIssueService},
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
pub(crate) struct HttpChallengeEndpointContext {
    service: ChallengeIssueService<PostgresChallengeRepository>,
    trusted_proxies: Vec<IpAddr>,
    requested: Arc<AtomicU64>,
    rate_limited: Arc<AtomicU64>,
}

impl FromRef<Arc<AppState>> for HttpChallengeEndpointContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: state.challenge_issue_service.clone(),
            trusted_proxies: state.config.trusted_proxy_ips.clone(),
            requested: Arc::clone(&state.metrics.anti_abuse_challenges_total),
            rate_limited: Arc::clone(&state.metrics.rate_limited_total),
        }
    }
}

impl HttpChallengeEndpointContext {
    pub(crate) fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub(crate) fn requested(&self) {
        self.requested.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn capacity_exhausted(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) async fn issue(
        &self,
        request: ChallengeIssueRequest<'_>,
    ) -> anyhow::Result<PowChallenge> {
        self.service.issue(request).await
    }
}
