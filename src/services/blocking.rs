//! Application boundary for XEP-0191 roster/blocking policy.

use anyhow::Result;
use uuid::Uuid;

pub(crate) type RosterEntry = (String, Option<String>, String, Option<String>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BlockUpdateOutcome {
    Changed(Vec<String>),
    QuotaExceeded,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UnblockUpdateOutcome {
    Changed(Vec<String>),
    Unavailable,
}

pub(crate) trait BlockingRepository: Send + Sync {
    fn blocked_jids(
        &self,
        owner: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
    fn roster(
        &self,
        owner: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<RosterEntry>>> + Send;
    fn block(
        &self,
        owner: Uuid,
        jids: &[String],
    ) -> impl std::future::Future<Output = Result<BlockUpdateOutcome>> + Send;
    fn unblock(
        &self,
        owner: Uuid,
        jids: Option<&[String]>,
    ) -> impl std::future::Future<Output = Result<UnblockUpdateOutcome>> + Send;
}
#[derive(Clone)]
pub(crate) struct BlockingService<R> {
    repository: R,
}
impl<R: BlockingRepository> BlockingService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn blocked_jids(&self, owner: Uuid) -> Result<Vec<String>> {
        self.repository.blocked_jids(owner).await
    }
    pub(crate) async fn roster(&self, owner: Uuid) -> Result<Vec<RosterEntry>> {
        self.repository.roster(owner).await
    }
    pub(crate) async fn block(&self, owner: Uuid, jids: &[String]) -> Result<BlockUpdateOutcome> {
        self.repository.block(owner, jids).await
    }
    pub(crate) async fn unblock(
        &self,
        owner: Uuid,
        jids: Option<&[String]>,
    ) -> Result<UnblockUpdateOutcome> {
        self.repository.unblock(owner, jids).await
    }
}
pub(crate) fn matches(pattern: &str, jid: &str) -> bool {
    northstar_xmpp_types::jid_scope_matches(pattern, jid)
}
