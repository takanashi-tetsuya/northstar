use super::{CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader};
use anyhow::Result;
use std::future::Future;

/// Policy for a captured account route, with an optional IQ roster grant.
pub trait ResourceCommunicationPolicyReader: CommunicationPolicyReader {
    fn read_resource_policy(
        &self,
        query: &CommunicationPolicyQuery,
        owner: (Option<&str>, &str),
        require_subscription: bool,
    ) -> impl Future<Output = Result<CommunicationDecision>> + Send;
}
