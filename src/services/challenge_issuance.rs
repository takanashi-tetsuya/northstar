//! Narrow capabilities for issuing and retiring anti-abuse challenges.

use crate::abuse::{AbuseAction, PowChallenge, PowIntent};
use anyhow::Result;
use std::future::Future;

pub(crate) struct ChallengeIssueRequest<'a> {
    pub(crate) action: AbuseAction,
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
    pub(crate) intent: Option<&'a PowIntent>,
}

pub(crate) trait ChallengeIssueRepository: Send + Sync {
    fn issue(
        &self,
        request: ChallengeIssueRequest<'_>,
    ) -> impl Future<Output = Result<PowChallenge>> + Send;
}

pub(crate) struct ChallengeIssueService<R> {
    repository: R,
}

impl<R: ChallengeIssueRepository> ChallengeIssueService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn issue(&self, request: ChallengeIssueRequest<'_>) -> Result<PowChallenge> {
        self.repository.issue(request).await
    }
}

pub(crate) trait ChallengeCleanupRepository: Send + Sync {
    fn cleanup(&self) -> impl Future<Output = Result<()>> + Send;
}

pub(crate) struct ChallengeCleanupService<R> {
    repository: R,
}

impl<R: ChallengeCleanupRepository> ChallengeCleanupService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn cleanup(&self) -> Result<()> {
        self.repository.cleanup().await
    }
}
