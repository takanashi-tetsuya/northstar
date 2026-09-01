//! Application boundary for XEP-0191 roster/blocking policy.

use crate::db;
use anyhow::Result;
use sqlx::PgPool;
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

#[derive(Clone)]
pub(crate) struct BlockingService {
    pool: PgPool,
}

impl BlockingService {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) async fn blocked_jids(&self, owner: Uuid) -> Result<Vec<String>> {
        db::blocked_jids(&self.pool, owner).await
    }

    pub(crate) async fn roster(&self, owner: Uuid) -> Result<Vec<RosterEntry>> {
        db::roster(&self.pool, owner).await
    }

    pub(crate) async fn block(&self, owner: Uuid, jids: &[String]) -> Result<BlockUpdateOutcome> {
        Ok(match db::block_jids(&self.pool, owner, jids).await? {
            db::BlockJidsUpdate::Changed(changed) => BlockUpdateOutcome::Changed(changed),
            db::BlockJidsUpdate::QuotaExceeded => BlockUpdateOutcome::QuotaExceeded,
            db::BlockJidsUpdate::Unavailable => BlockUpdateOutcome::Unavailable,
        })
    }

    pub(crate) async fn unblock(
        &self,
        owner: Uuid,
        jids: Option<&[String]>,
    ) -> Result<UnblockUpdateOutcome> {
        Ok(match db::unblock_jids(&self.pool, owner, jids).await? {
            db::UnblockJidsUpdate::Changed(changed) => UnblockUpdateOutcome::Changed(changed),
            db::UnblockJidsUpdate::Unavailable => UnblockUpdateOutcome::Unavailable,
        })
    }

    pub(crate) fn matches(pattern: &str, jid: &str) -> bool {
        db::blocked_jid_matches(pattern, jid)
    }
}
