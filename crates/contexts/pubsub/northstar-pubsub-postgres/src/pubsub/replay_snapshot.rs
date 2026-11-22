//! Subscription, node authority and latest-item reads for one replay page.

use super::{
    item::get_items_with_executor,
    node::get_node_with_executor,
    subscription::{node_authorization_facts_on, subscriptions_addressing_jid_page_on},
};
use anyhow::Result;
use northstar_pubsub_application::{replay_node_allows, replay_subscription_matches};
use northstar_pubsub_core::{
    PresenceReplayCandidate, PresenceReplayCursor, PresenceReplayPage, PresenceReplayQuery,
    PubSubSubscription,
};
use northstar_time::{DateTime, Utc};
use sqlx::{Postgres, Transaction};

/// Read candidate facts in the caller's read-only repeatable-read snapshot.
pub async fn read_presence_replay_candidates(
    transaction: &mut Transaction<'_, Postgres>,
    query: &PresenceReplayQuery,
    read_at: DateTime<Utc>,
) -> Result<PresenceReplayPage> {
    let recipient = query.recipient.to_string();
    let requester_bare = query.recipient.bare().to_string();
    let after = query
        .after
        .as_ref()
        .map(|cursor| (cursor.node.as_str(), cursor.jid.as_str()));
    let limit = query.limit.clamp(1, 100);
    let subscriptions = subscriptions_addressing_jid_page_on(
        &mut **transaction,
        &recipient,
        after,
        limit as i64,
        Some(read_at),
    )
    .await?;
    let scanned = subscriptions.len();
    let next = subscriptions
        .last()
        .filter(|_| scanned == limit)
        .map(|subscription| PresenceReplayCursor {
            node: subscription.node.clone(),
            jid: subscription.jid.clone(),
        });

    let mut candidates = Vec::new();
    for subscription in subscriptions.into_iter().map(PubSubSubscription::from) {
        if !replay_subscription_matches(&subscription, &query.show, read_at) {
            continue;
        }
        let Some(node) = get_node_with_executor(&mut **transaction, &subscription.node).await?
        else {
            continue;
        };
        let (affiliation, subscribed) = node_authorization_facts_on(
            &mut **transaction,
            node.id,
            &requester_bare,
            Some(read_at),
        )
        .await?;
        if !replay_node_allows(&node, affiliation.as_deref(), subscribed)? {
            continue;
        }
        let Some(item) = get_items_with_executor(&mut **transaction, node.id, &[], 1)
            .await?
            .into_iter()
            .next()
        else {
            continue;
        };
        candidates.push(PresenceReplayCandidate {
            subscription,
            node_id: node.id,
            node: node.node,
            deliver_payloads: node.deliver_payloads,
            item: item.into(),
        });
    }
    Ok(PresenceReplayPage::Candidates {
        candidates,
        next,
        scanned,
    })
}
