use anyhow::Result;
use northstar_pubsub_core::{PubSubBareJid, PubSubNodeName, PubSubOwnerPreflight};

/// Read the identity and authority used to prepare a generic owner command.
pub trait PubSubOwnerPreflightRepository: Send + Sync {
    fn owner_preflight(
        &self,
        node: &PubSubNodeName,
        requester: &PubSubBareJid,
        include_graph: bool,
    ) -> impl std::future::Future<Output = Result<Option<PubSubOwnerPreflight>>> + Send;
}
