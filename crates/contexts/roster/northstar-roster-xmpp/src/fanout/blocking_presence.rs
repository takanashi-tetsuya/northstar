use northstar_roster_application::blocking_mutation::{
    BlockingPresenceTarget, CommittedBlockingChange,
};
use northstar_xep_0191::{policy::effective_presence_transition, PresenceTransition, MAX_ITEMS};
use std::future::Future;

/// Hand off the committed plan in order, using the wire item bound.
pub async fn deliver_blocking_presence_change<F: Future<Output = ()>>(
    change: CommittedBlockingChange,
    mut send: impl FnMut(Vec<BlockingPresenceTarget>, bool) -> F,
) {
    let mut page = Vec::new();
    let mut available = false;
    for contact in change.contacts {
        let Some(transition) = effective_presence_transition(
            contact.covered_before,
            contact.covered_after,
            contact.other_policy_allows,
            contact.route.directed.is_some(),
        ) else {
            continue;
        };
        let restore = transition == PresenceTransition::RestoreCurrent;
        if !page.is_empty() && (page.len() == MAX_ITEMS || available != restore) {
            send(std::mem::take(&mut page), available).await;
        }
        available = restore;
        page.push(contact.route);
    }
    if !page.is_empty() {
        send(page, available).await;
    }
}

#[cfg(test)]
pub(super) mod tests;
