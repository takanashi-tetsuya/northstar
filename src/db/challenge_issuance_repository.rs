//! Persistence-backed anti-abuse challenge adapter.

use crate::{
    abuse::{AbuseGuard, PowChallenge},
    services::challenge_issuance::{
        ChallengeCleanupRepository, ChallengeIssueRepository, ChallengeIssueRequest,
    },
};
use anyhow::Result;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct PostgresChallengeRepository {
    guard: Arc<AbuseGuard>,
}

impl PostgresChallengeRepository {
    pub(crate) fn new(guard: Arc<AbuseGuard>) -> Self {
        Self { guard }
    }
}

impl ChallengeIssueRepository for PostgresChallengeRepository {
    async fn issue(&self, request: ChallengeIssueRequest<'_>) -> Result<PowChallenge> {
        match request.intent {
            Some(intent) => {
                self.guard
                    .issue_v2(request.action, request.subject, request.actors, intent)
                    .await
            }
            None => {
                self.guard
                    .issue(request.action, request.subject, request.actors)
                    .await
            }
        }
    }
}

impl ChallengeCleanupRepository for PostgresChallengeRepository {
    async fn cleanup(&self) -> Result<()> {
        self.guard.cleanup_challenges().await
    }
}
