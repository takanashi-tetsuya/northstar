//! Generic presence replay admission, authorized pages and digest projection.

use crate::PubSubService;
use anyhow::Result;
use northstar_pubsub_core::{
    PresenceReplayCandidate, PresenceReplayPage, PresenceReplayQuery, PubSubAddress, PubSubBareJid,
    PubSubNode, PubSubSubscription,
};
use northstar_time::{DateTime, Utc};
use std::future::Future;
use uuid::Uuid;

pub use northstar_pubsub_core::{ReplayDigestIntent, ReplayDigestOutcome};

pub(crate) const PRESENCE_REPLAY_PAGE_LIMIT: usize = 100;

#[derive(Clone, Debug)]
pub struct PresenceReplayAdmissionRequest {
    pub recipient_id: Uuid,
    pub active_privacy_list: Option<String>,
    pub connection_id: Uuid,
    pub service: PubSubBareJid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceReplayAdmissionOutcome {
    Blocked,
    Admitted,
}

/// Admit replay and refresh the connection's active privacy lease when applicable.
pub trait PresenceReplayAdmission: Send + Sync {
    fn admit_presence_replay(
        &self,
        request: PresenceReplayAdmissionRequest,
    ) -> impl Future<Output = Result<PresenceReplayAdmissionOutcome>> + Send;
}

/// Read policy, subscription and item facts in one snapshot for each page.
pub trait PubSubPresenceReplayQueryRepository: Send + Sync {
    fn presence_replay_page(
        &self,
        query: &PresenceReplayQuery,
    ) -> impl Future<Output = Result<PresenceReplayPage>> + Send;
}

/// Revalidate an accepted replay candidate before writing to the digest outbox.
pub trait PubSubReplayDigestRepository: Send + Sync {
    fn enqueue_replay_digest(
        &self,
        intent: ReplayDigestIntent,
    ) -> impl Future<Output = Result<ReplayDigestOutcome>> + Send;
}

pub fn replay_subscription_matches(
    subscription: &PubSubSubscription,
    show: &str,
    read_at: DateTime<Utc>,
) -> bool {
    subscription.is_active_at(read_at)
        && subscription.deliver
        && subscription.show_values.iter().any(|value| value == show)
}

pub fn replay_node_allows(
    node: &PubSubNode,
    affiliation: Option<&str>,
    subscribed: bool,
) -> Result<bool> {
    if node.send_last_published_item != "on_sub_and_presence" {
        return Ok(false);
    }
    let affiliation = affiliation
        .map(str::parse::<northstar_xep_0060::Affiliation>)
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid stored PubSub affiliation: {error}"))?;
    let access_model = node
        .access_model
        .parse::<northstar_xep_0060::AccessModel>()
        .map_err(|error| anyhow::anyhow!("invalid stored PubSub access model: {error}"))?;
    Ok(northstar_xep_0060::can_retrieve_pure(
        access_model,
        affiliation,
        subscribed,
    ))
}

impl<R: PubSubPresenceReplayQueryRepository + PubSubReplayDigestRepository> PubSubService<R> {
    /// Render candidates in page order and stop if the outbound sink closes.
    pub async fn replay_presence_pages<F>(
        &self,
        mut query: PresenceReplayQuery,
        render: impl Fn(&PresenceReplayCandidate) -> Result<String> + Send,
        mut send: impl FnMut(String) -> F + Send,
    ) -> Result<()>
    where
        F: Future<Output = Result<bool>> + Send,
    {
        query.limit = if query.limit == 0 {
            PRESENCE_REPLAY_PAGE_LIMIT
        } else {
            query.limit.min(PRESENCE_REPLAY_PAGE_LIMIT)
        };
        loop {
            let PresenceReplayPage::Candidates {
                candidates,
                next,
                scanned,
            } = self.presence_replay_page(&query).await?
            else {
                return Ok(());
            };
            for candidate in candidates {
                let children = render(&candidate)?;
                if candidate.subscription.digest {
                    let outcome = self
                        .enqueue_replay_digest(ReplayDigestIntent {
                            node_id: candidate.node_id,
                            subid: candidate.subscription.subid,
                            subscriber_jid: PubSubAddress::parse(&candidate.subscription.jid)?,
                            digest_frequency: candidate.subscription.digest_frequency,
                            item_id: candidate.item.item_id,
                            children: children.clone(),
                        })
                        .await?;
                    if outcome != ReplayDigestOutcome::NotDigest {
                        continue;
                    }
                }
                if !send(children).await? {
                    return Ok(());
                }
            }
            let Some(next) = next.filter(|_| scanned >= query.limit) else {
                return Ok(());
            };
            query.after = Some(next);
        }
    }
}

#[cfg(test)]
mod tests;
