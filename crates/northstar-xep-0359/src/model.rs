//! Typed wire values and identity keys for XEP-0359.

use northstar_xmpp_types::jid::CanonicalJid;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StableId<'a>(&'a str);

impl<'a> StableId<'a> {
    pub(crate) const fn new_validated(value: &'a str) -> Self {
        Self(value)
    }

    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginId<'a> {
    pub id: StableId<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StanzaId<'a> {
    pub id: StableId<'a>,
    pub by: CanonicalJid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferencedStanza<'a> {
    pub id: StableId<'a>,
    pub by: Option<CanonicalJid>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MessageIds<'a> {
    pub origin: Option<OriginId<'a>>,
    pub stanza_ids: Vec<StanzaId<'a>>,
    pub references: Vec<ReferencedStanza<'a>>,
    pub unknown_sid_children: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum DeduplicationKey<'a> {
    /// Spoofable client identity, valid only inside a caller-supplied sender scope.
    Origin {
        sender_scope: CanonicalJid,
        id: StableId<'a>,
    },
    /// Entity-issued identity. Trust still depends on the assigning entity
    /// advertising and following XEP-0359 business rules.
    Authoritative { by: CanonicalJid, id: StableId<'a> },
}
