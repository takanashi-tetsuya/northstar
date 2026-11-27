//! A blocking command and its committed presence audience.

use crate::{CommunicationPolicyQuery, ExactPresenceRoute, PolicyDirection, PolicySubject};
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockingMutation {
    Block(Vec<CanonicalJid>),
    Unblock(Vec<CanonicalJid>),
    UnblockAll,
}

impl BlockingMutation {
    pub fn patterns(&self) -> Option<&[CanonicalJid]> {
        match self {
            Self::Block(patterns) | Self::Unblock(patterns) => Some(patterns),
            Self::UnblockAll => None,
        }
    }
}

/// Runtime facts sampled before entering the database transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockingRouteCandidate {
    pub route: ExactPresenceRoute,
    pub available: bool,
    pub expects_active: bool,
    pub directed: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockingMutationOutcome {
    Committed(CommittedBlockingChange),
    QuotaExceeded,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedBlockingChange {
    pub delta: Vec<String>,
    pub contacts: Vec<BlockingContactTransition>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockingContactTransition {
    pub route: BlockingPresenceTarget,
    pub covered_before: bool,
    pub covered_after: bool,
    pub other_policy_allows: bool,
}

/// One captured source and destination. For federation, the destination is
/// the addressed remote JID; its server owns the recipient-side policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockingPresenceTarget {
    pub source: ExactPresenceRoute,
    pub source_expects_active: bool,
    pub recipient: Option<ExactPresenceRoute>,
    pub recipient_expects_active: bool,
    pub address: String,
    /// An existing directed grant from this source, if any.
    pub directed: Option<String>,
}

impl BlockingPresenceTarget {
    pub fn policies(&self, check_source_block: bool) -> [Option<CommunicationPolicyQuery>; 2] {
        let peer = self
            .recipient
            .as_ref()
            .map_or(&self.address, |r| &r.full_jid);
        [
            Some(presence_policy(
                &self.source,
                self.source_expects_active,
                peer,
                PolicyDirection::Outbound,
                check_source_block,
            )),
            self.recipient.as_ref().map(|recipient| {
                presence_policy(
                    recipient,
                    self.recipient_expects_active,
                    &self.source.full_jid,
                    PolicyDirection::Inbound,
                    true,
                )
            }),
        ]
    }
}

fn presence_policy(
    route: &ExactPresenceRoute,
    expects_active: bool,
    peer: &str,
    direction: PolicyDirection,
    check_owner_block: bool,
) -> CommunicationPolicyQuery {
    CommunicationPolicyQuery {
        account_id: route.account_id,
        expected_auth_generation: Some(route.auth_generation),
        subject: PolicySubject::Connection {
            connection_id: route.connection_id,
            expects_active,
        },
        peer: peer.to_owned(),
        kind: match direction {
            PolicyDirection::Inbound => PrivacyStanzaKind::PresenceIn,
            PolicyDirection::Outbound => PrivacyStanzaKind::PresenceOut,
        },
        direction,
        check_owner_block,
        check_peer_block: false,
    }
}
