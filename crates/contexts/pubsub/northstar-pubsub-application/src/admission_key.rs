//! Typed mutation admission keys that hash to the same stripes as the existing string keys.

use crate::{PubSubMutationAdmission, PubSubMutationPermit};
use anyhow::Result;
use northstar_pubsub_core::{PubSubAddress, PubSubBareJid, PubSubNodeId, PubSubNodeName};
use std::borrow::Cow;
use std::time::Duration;
use uuid::Uuid;

/// A PubSub mutation admission key with the same text as existing string keys.
/// `Owner` and `NodeId` for the same UUID produce the same key.
#[derive(Clone, Copy, Debug)]
pub enum PubSubAdmissionKey<'a> {
    /// An existing key string used as supplied.
    Text(&'a str),
    /// A stored node identified by its UUID.
    NodeId(PubSubNodeId),
    /// An owner account identified by its UUID.
    Owner(Uuid),
    /// A canonical JID with any resourcepart preserved.
    Address(&'a PubSubAddress),
    /// A canonical bare JID.
    Bare(&'a PubSubBareJid),
    /// A node name with its original text preserved.
    NodeName(&'a PubSubNodeName),
}

impl<'a> PubSubAdmissionKey<'a> {
    /// Return the exact text to hash for this key, borrowing it when available.
    pub fn compat_text(&self) -> Cow<'a, str> {
        match *self {
            Self::Text(text) => Cow::Borrowed(text),
            Self::NodeId(id) => Cow::Owned(id.to_string()),
            Self::Owner(id) => Cow::Owned(id.to_string()),
            Self::Address(address) => Cow::Owned(address.to_string()),
            Self::Bare(jid) => Cow::Owned(jid.to_string()),
            Self::NodeName(name) => Cow::Borrowed(name.as_str()),
        }
    }
}

impl PubSubMutationAdmission {
    /// Acquire admission for the existing stripes of these keys with the default timeout.
    pub async fn acquire_keys(
        &self,
        keys: &[PubSubAdmissionKey<'_>],
        graph: bool,
    ) -> Result<PubSubMutationPermit> {
        let texts: Vec<_> = keys.iter().map(PubSubAdmissionKey::compat_text).collect();
        let keys: Vec<_> = texts.iter().map(Cow::as_ref).collect();
        self.acquire(&keys, graph).await
    }

    /// Acquire admission for the existing stripes of these keys with the supplied timeout.
    pub async fn acquire_keys_with_timeout(
        &self,
        keys: &[PubSubAdmissionKey<'_>],
        graph: bool,
        wait: Duration,
    ) -> Result<PubSubMutationPermit> {
        let texts: Vec<_> = keys.iter().map(PubSubAdmissionKey::compat_text).collect();
        let keys: Vec<_> = texts.iter().map(Cow::as_ref).collect();
        self.acquire_with_timeout(&keys, graph, wait).await
    }
}

#[cfg(test)]
mod tests;
