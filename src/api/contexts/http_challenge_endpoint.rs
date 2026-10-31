//! Public proof-of-work issuance; bearer lookup remains with the API query context.

use crate::db::challenge_issuance_repository::PostgresChallengeRepository;
use northstar_abuse_application::challenge::{ChallengeIssueRequest, ChallengeIssueService};
use northstar_abuse_policy::PowChallenge;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[derive(Clone)]
pub(crate) struct HttpChallengeEndpointContext {
    pub(crate) service: ChallengeIssueService<PostgresChallengeRepository>,
    pub(crate) trusted_proxies: Vec<IpAddr>,
    pub(crate) requested: Arc<AtomicU64>,
    pub(crate) rate_limited: Arc<AtomicU64>,
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
