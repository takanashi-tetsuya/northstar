//! Pure authority, replacement and deduplication decisions.

use crate::model::{DeduplicationKey, MessageIds, StableId};
use northstar_xmpp_types::jid::CanonicalJid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityUpdate<'a> {
    pub assigning_entity: CanonicalJid,
    pub remove_matching: usize,
    pub foreign_ids_preserved: usize,
    pub replacement: Option<StableId<'a>>,
    pub preserve_origin: bool,
}

/// Apply the XEP-0359 rule that an assigning entity removes every existing
/// direct stanza-id bearing its own canonical `by`, even when it chooses not
/// to add a replacement.
pub fn plan_authority_update<'a>(
    ids: &MessageIds<'_>,
    assigning_entity: CanonicalJid,
    replacement: Option<StableId<'a>>,
) -> AuthorityUpdate<'a> {
    let remove_matching = ids
        .stanza_ids
        .iter()
        .filter(|item| item.by == assigning_entity)
        .count();
    AuthorityUpdate {
        assigning_entity,
        remove_matching,
        foreign_ids_preserved: ids.stanza_ids.len().saturating_sub(remove_matching),
        replacement,
        preserve_origin: ids.origin.is_some(),
    }
}

pub fn origin_deduplication_key<'a>(
    sender_scope: CanonicalJid,
    id: StableId<'a>,
) -> DeduplicationKey<'a> {
    DeduplicationKey::Origin { sender_scope, id }
}

pub fn authoritative_deduplication_key<'a>(
    by: CanonicalJid,
    id: StableId<'a>,
) -> DeduplicationKey<'a> {
    DeduplicationKey::Authoritative { by, id }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceTrust {
    /// `origin-id` is client supplied and spoofable outside a trusted sender scope.
    SpoofableOrigin,
    /// The `by` entity has not been verified to advertise XEP-0359 support.
    UnverifiedAssigningEntity,
    /// The assigning entity advertises XEP-0359 and the caller has authenticated
    /// the route on which the stanza was received.
    VerifiedAssigningEntity,
}

pub const fn stanza_id_trust(assigning_entity_supports_xep: bool) -> ReferenceTrust {
    if assigning_entity_supports_xep {
        ReferenceTrust::VerifiedAssigningEntity
    } else {
        ReferenceTrust::UnverifiedAssigningEntity
    }
}
