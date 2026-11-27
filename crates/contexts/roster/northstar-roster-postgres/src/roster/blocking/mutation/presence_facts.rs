use super::MAX_BLOCKED_JIDS_PER_ACCOUNT;
use crate::{
    privacy::read_communication_policies,
    roster::{blocking_match_candidates, roster_page_after},
};
use anyhow::Result;
use northstar_roster_application::blocking_mutation::{
    BlockingContactTransition, BlockingPresenceTarget, BlockingRouteCandidate,
};
use northstar_roster_application::{CommunicationDecision, RosterActor};
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{Postgres, Transaction};
use std::collections::{BTreeSet, HashSet};

pub(super) async fn capture(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &RosterActor,
    routes: &[BlockingRouteCandidate],
    before: &[String],
    delta: &[String],
) -> Result<Vec<BlockingContactTransition>> {
    let owner = CanonicalJid::parse(&actor.full_jid)?;
    let mut sources = routes
        .iter()
        .filter(|source| {
            source.available
                && source.route.account_id == actor.account_id
                && source.route.auth_generation == actor.auth_generation
                && bare(&source.route.full_jid) == actor.bare_jid()
        })
        .collect::<Vec<_>>();
    if sources.is_empty() {
        return Ok(Vec::new());
    }
    sources.sort_unstable_by(|left, right| left.route.full_jid.cmp(&right.route.full_jid));

    let mut roster = BTreeSet::new();
    let mut after = None;
    loop {
        let page = roster_page_after(
            &mut **transaction,
            actor.account_id,
            after.as_deref(),
            MAX_BLOCKED_JIDS_PER_ACCOUNT as i64,
        )
        .await?;
        after = page.last().map(|(jid, ..)| jid.clone());
        let last_page = page.len() < MAX_BLOCKED_JIDS_PER_ACCOUNT;
        roster.extend(page.into_iter().filter_map(|(jid, _, subscription, _)| {
            (matches!(subscription.as_str(), "from" | "both") && jid != actor.bare_jid())
                .then_some(jid)
        }));
        if last_page {
            break;
        }
    }

    let before_set = before.iter().map(String::as_str).collect::<HashSet<_>>();
    let delta_set = delta.iter().map(String::as_str).collect::<HashSet<_>>();
    let mut after_set = before_set.clone();
    for pattern in delta {
        if !after_set.remove(pattern.as_str()) {
            after_set.insert(pattern.as_str());
        }
    }
    let mut recipients = routes
        .iter()
        .filter(|route| {
            route.route.account_id != actor.account_id && covers(&delta_set, &route.route.full_jid)
        })
        .collect::<Vec<_>>();
    recipients.sort_unstable_by(|left, right| left.route.full_jid.cmp(&right.route.full_jid));

    let mut contacts = Vec::new();
    for source in sources {
        let directed = source
            .directed
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for recipient in &recipients {
            let full = recipient.route.full_jid.as_str();
            let bare = bare(full);
            let roster_grant = roster.contains(bare);
            let bare_grant = recipient.available && directed.contains(bare);
            let full_grant = directed.contains(full);
            let exact_change = delta_set.contains(full);
            let address = if (roster_grant || bare_grant)
                && recipient.available
                && covers(&delta_set, bare)
            {
                bare
            } else if full_grant || (exact_change && (roster_grant || bare_grant)) {
                full
            } else {
                continue;
            };
            let grant = if full_grant {
                Some(full)
            } else {
                bare_grant.then_some(bare)
            };
            contacts.push(transition(
                source,
                Some(recipient),
                address,
                grant,
                &before_set,
                &after_set,
            ));
        }

        let external = roster
            .iter()
            .map(String::as_str)
            .chain(
                delta
                    .iter()
                    .map(String::as_str)
                    .filter(|key| bare(key) != *key && roster.contains(bare(key))),
            )
            .chain(directed.iter().copied())
            .filter(|address| {
                CanonicalJid::parse(address).is_ok_and(|jid| jid.domainpart() != owner.domainpart())
                    && covers(&delta_set, address)
            })
            .collect::<BTreeSet<_>>();
        for address in external {
            contacts.push(transition(
                source,
                None,
                address,
                directed.get(address).copied(),
                &before_set,
                &after_set,
            ));
        }
    }

    for page in contacts.chunks_mut(MAX_BLOCKED_JIDS_PER_ACCOUNT) {
        let queries = page
            .iter()
            .flat_map(|contact| contact.route.policies(false).into_iter().flatten())
            .collect::<Vec<_>>();
        let decisions = read_communication_policies(&mut **transaction, &queries).await?;
        let mut decisions = decisions.into_iter();
        for contact in page {
            let source = decisions.next();
            let recipient = contact.route.recipient.is_none()
                || decisions.next() == Some(CommunicationDecision::Allow);
            contact.other_policy_allows = source == Some(CommunicationDecision::Allow) && recipient;
        }
    }
    Ok(contacts)
}

fn transition(
    source: &BlockingRouteCandidate,
    recipient: Option<&BlockingRouteCandidate>,
    address: &str,
    directed: Option<&str>,
    before: &HashSet<&str>,
    after: &HashSet<&str>,
) -> BlockingContactTransition {
    let peer = recipient.map_or(address, |route| route.route.full_jid.as_str());
    BlockingContactTransition {
        route: BlockingPresenceTarget {
            source: source.route.clone(),
            source_expects_active: source.expects_active,
            recipient: recipient.map(|recipient| recipient.route.clone()),
            recipient_expects_active: recipient.is_some_and(|recipient| recipient.expects_active),
            address: address.to_owned(),
            directed: directed.map(str::to_owned),
        },
        covered_before: covers(before, peer),
        covered_after: covers(after, peer),
        other_policy_allows: false,
    }
}

fn covers(patterns: &HashSet<&str>, peer: &str) -> bool {
    CanonicalJid::parse(peer).is_ok_and(|peer| {
        blocking_match_candidates(&peer)
            .iter()
            .any(|key| patterns.contains(key.as_str()))
    })
}

fn bare(jid: &str) -> &str {
    northstar_xmpp_types::jid_text::bare_jid(jid)
}
