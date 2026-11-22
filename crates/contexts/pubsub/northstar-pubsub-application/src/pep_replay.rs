//! Read port and selection policy for PEP send-last.

use crate::PubSubService;
use anyhow::Result;
use northstar_pubsub_core::{
    PepNodeConfig, PepReplayMode, PepReplayOrigin, PepReplayPage, PepReplayQuery, PubSubBareJid,
};

pub const DEFAULT_PEP_REPLAY_LIMIT: usize = 100;

pub trait PepReplayQueryRepository: Send + Sync {
    fn pep_replay_page(
        &self,
        query: &PepReplayQuery,
    ) -> impl std::future::Future<Output = Result<PepReplayPage>> + Send;
}

impl<R: PepReplayQueryRepository> PubSubService<R> {
    pub async fn pep_replay_page(&self, query: &PepReplayQuery) -> Result<PepReplayPage> {
        if query.limit == 0 {
            let query = PepReplayQuery {
                limit: DEFAULT_PEP_REPLAY_LIMIT,
                ..query.clone()
            };
            return self.repository.pep_replay_page(&query).await;
        }
        self.repository.pep_replay_page(query).await
    }
}

/// Determines whether the requester can use this replay mode at this address.
pub fn pep_replay_request_allowed(query: &PepReplayQuery) -> bool {
    let requester = query.requester.canonical();
    match &query.mode {
        PepReplayMode::AfterSubscribe { .. } => true,
        PepReplayMode::Explicit => query.requester.has_resource(),
        PepReplayMode::LocalCaps { wanted } => {
            !wanted.is_empty()
                && query.requester.has_resource()
                && requester.domainpart() == query.local_domain
                && requester.localpart().is_some()
        }
        PepReplayMode::FederatedCaps { wanted } => {
            !wanted.is_empty()
                && query.requester.has_resource()
                && requester.domainpart() != query.local_domain
        }
    }
}

/// The local caps owner comes from the requester itself or a local roster contact
/// whose presence the requester is subscribed to.
pub fn pep_replay_local_owner(
    query: &PepReplayQuery,
    contact: Option<(&str, &str)>,
) -> Option<String> {
    match contact {
        None => query.requester.canonical().localpart().map(str::to_owned),
        Some((jid, "to" | "both")) => {
            let contact = PubSubBareJid::parse(jid).ok()?;
            let contact = contact.canonical();
            if contact.domainpart() != query.local_domain {
                return None;
            }
            contact.localpart().map(str::to_owned)
        }
        Some(_) => None,
    }
}

/// Selects the replay origin from the node policy and the matching subscription
/// fact. The explicit subscription wins even when another delivery gate denies it.
pub fn pep_replay_origin(
    mode: &PepReplayMode,
    config: &PepNodeConfig,
    has_explicit_subscription: bool,
) -> Option<PepReplayOrigin> {
    let on_presence = match mode {
        PepReplayMode::AfterSubscribe { on_presence, .. } => *on_presence,
        _ => true,
    };
    if !config.deliver_notifications
        || config.send_last_published_item == "never"
        || on_presence && config.send_last_published_item != "on_sub_and_presence"
    {
        return None;
    }
    match mode {
        PepReplayMode::Explicit | PepReplayMode::AfterSubscribe { .. }
            if has_explicit_subscription =>
        {
            Some(PepReplayOrigin::Explicit)
        }
        PepReplayMode::LocalCaps { .. } | PepReplayMode::FederatedCaps { .. }
            if !has_explicit_subscription =>
        {
            Some(PepReplayOrigin::Automatic)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
