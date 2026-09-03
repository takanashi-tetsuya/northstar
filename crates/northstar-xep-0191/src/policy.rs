//! Pure blocking match and presence-transition planning.

use crate::model::{
    BlockPattern, BlockingEffects, BlockingMutation, PresencePeer, PresenceTransition,
};
use northstar_xmpp_types::jid::CanonicalJid;
use std::collections::BTreeSet;

pub fn plan_blocking_effects(
    mutation: BlockingMutation,
    changed: &[BlockPattern],
    roster: &[PresencePeer],
    directed_presence: &[CanonicalJid],
) -> BlockingEffects {
    let presence_transition = if matches!(mutation, BlockingMutation::Block(_)) {
        PresenceTransition::SendUnavailable
    } else {
        PresenceTransition::RestoreCurrent
    };
    let presence_targets = presence_targets(changed, roster, directed_presence);
    BlockingEffects {
        push_mutation: mutation,
        presence_transition,
        presence_targets,
    }
}

pub fn presence_targets(
    changed: &[BlockPattern],
    roster: &[PresencePeer],
    directed_presence: &[CanonicalJid],
) -> Vec<CanonicalJid> {
    let mut targets = BTreeSet::new();
    for pattern in changed {
        let pattern_jid = pattern.jid();
        if pattern_jid.resourcepart().is_some() {
            let permission_bare = pattern_jid.bare();
            if roster.iter().any(|entry| {
                entry.jid.bare() == permission_bare
                    && entry.subscription.may_receive_owner_presence()
            }) {
                targets.insert(pattern_jid.clone());
            }
        } else {
            for entry in roster {
                if entry.subscription.may_receive_owner_presence() && pattern.matches(&entry.jid) {
                    targets.insert(entry.jid.to_bare());
                }
            }
        }
        for directed in directed_presence {
            if pattern.matches(directed) {
                targets.insert(directed.clone());
            }
        }
    }
    targets.into_iter().collect()
}
