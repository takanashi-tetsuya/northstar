//! Public proof-of-work issuance; bearer lookup remains with the API query context.

use crate::repositories::HttpRepositories;
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
pub struct HttpChallengeEndpointContext<R: HttpRepositories> {
    pub service: ChallengeIssueService<R::Challenges>,
    pub trusted_proxies: Vec<IpAddr>,
    pub requested: Arc<AtomicU64>,
    pub rate_limited: Arc<AtomicU64>,
}

impl<R: HttpRepositories> HttpChallengeEndpointContext<R> {
    pub fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub fn requested(&self) {
        self.requested.fetch_add(1, Ordering::Relaxed);
    }

    pub fn capacity_exhausted(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn issue(&self, request: ChallengeIssueRequest<'_>) -> anyhow::Result<PowChallenge> {
        self.service.issue(request).await
    }
}
