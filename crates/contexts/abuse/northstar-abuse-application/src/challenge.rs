//! Narrow capabilities for issuing and retiring anti-abuse challenges.

use anyhow::Result;
use northstar_abuse_policy::{AbuseAction, PowChallenge, PowIntent};
use std::future::Future;

pub struct ChallengeIssueRequest<'a> {
    pub action: AbuseAction,
    pub subject: &'a str,
    pub actors: &'a [String],
    pub intent: Option<&'a PowIntent>,
}

pub trait ChallengeIssueRepository: Send + Sync {
    fn issue(
        &self,
        request: ChallengeIssueRequest<'_>,
    ) -> impl Future<Output = Result<PowChallenge>> + Send;
}

#[derive(Clone)]
pub struct ChallengeIssueService<R> {
    repository: R,
}

impl<R: ChallengeIssueRepository> ChallengeIssueService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn issue(&self, request: ChallengeIssueRequest<'_>) -> Result<PowChallenge> {
        self.repository.issue(request).await
    }
}

pub trait ChallengeCleanupRepository: Send + Sync {
    fn cleanup(&self) -> impl Future<Output = Result<()>> + Send;
}

#[derive(Clone)]
pub struct ChallengeCleanupService<R> {
    repository: R,
}

impl<R: ChallengeCleanupRepository> ChallengeCleanupService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn cleanup(&self) -> Result<()> {
        self.repository.cleanup().await
    }
}
