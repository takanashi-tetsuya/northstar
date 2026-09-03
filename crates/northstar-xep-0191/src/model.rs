//! Typed XEP-0191 commands and blocking snapshots.

use northstar_xmpp_types::jid::CanonicalJid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockingCommand {
    GetBlocklist,
    Mutate(BlockingMutation),
}

/// A state-changing blocking command.
///
/// Keeping mutations separate from [`BlockingCommand::GetBlocklist`] makes it
/// impossible to accidentally plan presence transitions for a read-only IQ.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockingMutation {
    Block(Vec<BlockPattern>),
    Unblock(Vec<BlockPattern>),
    UnblockAll,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockPattern(CanonicalJid);

impl BlockPattern {
    pub fn new(jid: CanonicalJid) -> Self {
        Self(jid)
    }

    pub fn jid(&self) -> &CanonicalJid {
        &self.0
    }

    pub fn into_jid(self) -> CanonicalJid {
        self.0
    }

    pub fn matches(&self, candidate: &CanonicalJid) -> bool {
        if self.0.resourcepart().is_some() {
            self.0 == *candidate
        } else if self.0.localpart().is_some() {
            self.0.bare() == candidate.bare()
        } else {
            self.0.domainpart() == candidate.domainpart()
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockingSnapshot {
    patterns: Vec<BlockPattern>,
}

impl BlockingSnapshot {
    pub fn new(mut patterns: Vec<BlockPattern>) -> Self {
        patterns.sort_unstable();
        patterns.dedup();
        Self { patterns }
    }

    pub fn patterns(&self) -> &[BlockPattern] {
        &self.patterns
    }

    pub fn is_blocked(&self, candidate: &CanonicalJid) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.matches(candidate))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Subscription {
    None,
    To,
    From,
    Both,
}

impl Subscription {
    pub const fn may_receive_owner_presence(self) -> bool {
        matches!(self, Self::From | Self::Both)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresencePeer {
    pub jid: CanonicalJid,
    pub subscription: Subscription,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceTransition {
    SendUnavailable,
    RestoreCurrent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockingEffects {
    pub push_mutation: BlockingMutation,
    pub presence_transition: PresenceTransition,
    pub presence_targets: Vec<CanonicalJid>,
}
