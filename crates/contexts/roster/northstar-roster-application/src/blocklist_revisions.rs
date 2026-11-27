use anyhow::Result;
use northstar_roster_core::RosterActor;
use std::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlocklistAction {
    Block,
    Unblock,
    UnblockAll,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlocklistChange {
    pub revision: i64,
    pub action: BlocklistAction,
    pub patterns: Vec<String>,
}

pub struct BlocklistSnapshot {
    pub revision: i64,
    pub patterns: Vec<String>,
}

pub struct BlocklistJournal {
    pub revision: i64,
    pub changes: Vec<BlocklistChange>,
}

pub trait BlocklistRevisionRepository: Send + Sync {
    fn blocklist_snapshot(
        &self,
        actor: &RosterActor,
    ) -> impl Future<Output = Result<Option<BlocklistSnapshot>>> + Send;

    /// `None` reads only the newest change, if any. Otherwise read the bounded
    /// prefix after the cursor together with the head from the same snapshot.
    fn blocklist_journal(
        &self,
        actor: &RosterActor,
        after: Option<i64>,
    ) -> impl Future<Output = Result<Option<BlocklistJournal>>> + Send;
}
