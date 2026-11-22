//! Typed PubSub authority: canonical addresses, bare JIDs, node ids and node names.

use anyhow::{ensure, Result};
use northstar_xmpp_types::CanonicalJid;
use std::fmt;
use uuid::Uuid;

/// A canonical PubSub address that preserves any resourcepart.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PubSubAddress(CanonicalJid);

impl PubSubAddress {
    /// Parse and canonicalize a bare or full JID.
    pub fn parse(value: &str) -> Result<Self> {
        CanonicalJid::parse(value).map(Self)
    }

    /// Wrap an already canonical JID as a PubSub address.
    pub fn from_canonical(jid: CanonicalJid) -> Self {
        Self(jid)
    }

    /// Borrow the canonical JID, including any resourcepart.
    pub fn canonical(&self) -> &CanonicalJid {
        &self.0
    }

    /// Return whether the canonical address includes a resourcepart.
    pub fn has_resource(&self) -> bool {
        self.0.resourcepart().is_some()
    }

    /// Return the canonical bare JID for this address.
    pub fn bare(&self) -> PubSubBareJid {
        PubSubBareJid(self.0.to_bare())
    }
}

impl fmt::Display for PubSubAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A canonical account or service JID without a resourcepart.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PubSubBareJid(CanonicalJid);

impl PubSubBareJid {
    /// Parse and canonicalize a bare JID, rejecting resourceparts.
    pub fn parse(value: &str) -> Result<Self> {
        CanonicalJid::parse_bare(value).map(Self)
    }

    /// Borrow the canonical bare JID.
    pub fn canonical(&self) -> &CanonicalJid {
        &self.0
    }
}

impl fmt::Display for PubSubBareJid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The stored UUID identifying a PubSub node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PubSubNodeId(Uuid);

impl PubSubNodeId {
    /// Wrap the node's stored UUID.
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// Return the node's stored UUID.
    pub fn get(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for PubSubNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A PubSub node name that preserves its original text and contains non-whitespace.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PubSubNodeName(String);

impl PubSubNodeName {
    /// Preserve the supplied node name if it contains non-whitespace.
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(!value.trim().is_empty(), "node must not be empty");
        Ok(Self(value.to_owned()))
    }

    /// Borrow the original node name text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PubSubNodeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests;
