//! Read-only XEP-0191 and XEP-0016 admission for a captured account.

use anyhow::Result;
use northstar_xep_0016::PrivacyStanzaKind;
use std::future::Future;
use uuid::Uuid;

mod test_support;
pub use test_support::InMemoryCommunicationPolicyReader;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyDirection {
    /// The local account receives a stanza from the peer.
    Inbound,
    /// The local account sends a stanza to the peer.
    Outbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicySubject {
    /// Use the live selection, with the default as fallback. If an active
    /// selection is expected, a missing or expired lease denies access.
    Connection {
        connection_id: Uuid,
        expects_active: bool,
    },
    /// Use the account default regardless of its connected resources.
    AccountDefault,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunicationPolicyQuery {
    pub account_id: Uuid,
    pub expected_auth_generation: Option<i64>,
    pub subject: PolicySubject,
    /// The canonical JID as carried by the stanza, including any resource.
    pub peer: String,
    /// For presence, supply the mask that corresponds to the direction.
    pub kind: PrivacyStanzaKind,
    pub direction: PolicyDirection,
    /// Match the peer against the local account's blocklist. The gate decides
    /// whether blocking applies to this stanza, including same-account traffic.
    pub check_owner_block: bool,
    /// Set when a reverse check is requested and the peer is on the local
    /// account domain. Match the owner's bare JID against that peer's blocklist.
    pub check_peer_block: bool,
}

/// Decisions are ordered from least to highest precedence. Blocking takes
/// precedence over privacy to preserve existing error precedence. Callers map
/// the decision to the wire error for their gate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CommunicationDecision {
    Allow,
    PrivacyDenies,
    PeerBlocks,
    OwnerBlocks,
    /// The local account is missing, disabled, or has a different auth generation.
    StaleAccount,
}

impl CommunicationDecision {
    pub fn allows(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

pub trait CommunicationPolicyReader: Send + Sync {
    /// Sample the batch in one read snapshot. Each query gets a decision in
    /// input order. This read does not extend or repair any selection lease.
    fn read_communication_policies(
        &self,
        queries: &[CommunicationPolicyQuery],
    ) -> impl Future<Output = Result<Vec<CommunicationDecision>>> + Send;

    fn read_communication_policy(
        &self,
        query: &CommunicationPolicyQuery,
    ) -> impl Future<Output = Result<CommunicationDecision>> + Send {
        let read = self.read_communication_policies(std::slice::from_ref(query));
        async move {
            let decisions = read.await?;
            match decisions.as_slice() {
                [decision] => Ok(*decision),
                _ => anyhow::bail!("expected one communication policy decision"),
            }
        }
    }
}

#[cfg(test)]
mod tests;
