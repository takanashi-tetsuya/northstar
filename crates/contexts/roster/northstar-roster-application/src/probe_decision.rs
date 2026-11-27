use crate::{CommunicationPolicyQuery, CommunicationPolicyReader, PolicyDirection, PolicySubject};
use anyhow::Result;
use northstar_roster_core::{ExactPresenceRoute, PresenceAccount, RosterActor};
use northstar_xep_0016::PrivacyStanzaKind;
use std::future::Future;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresenceRoute {
    pub exact: ExactPresenceRoute,
    /// A remote route may have no in-memory selector sample. Its receiving
    /// node must check its own selection before accepting the stanza.
    pub active_list: Option<String>,
}

impl PresenceRoute {
    pub fn policy(&self, peer: &str, direction: PolicyDirection) -> CommunicationPolicyQuery {
        let kind = match direction {
            PolicyDirection::Inbound => PrivacyStanzaKind::PresenceIn,
            PolicyDirection::Outbound => PrivacyStanzaKind::PresenceOut,
        };
        CommunicationPolicyQuery {
            account_id: self.exact.account_id,
            expected_auth_generation: Some(self.exact.auth_generation),
            subject: PolicySubject::Connection {
                connection_id: self.exact.connection_id,
                expects_active: self.active_list.is_some(),
            },
            peer: peer.to_owned(),
            kind,
            direction,
            check_owner_block: true,
            check_peer_block: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeCandidate {
    pub route: PresenceRoute,
    pub available: bool,
    /// Only valid for the captured owner connection and this requester.
    pub directed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeQuery<'a> {
    pub owner: &'a PresenceAccount,
    pub target: &'a str,
    pub requester: &'a str,
    pub candidates: &'a [ProbeCandidate],
    /// Local request/replay routes. Empty for a verified federated requester.
    pub recipients: &'a [PresenceRoute],
    /// True for an incoming probe. Approval and initial replay only send
    /// available presence and must still have a current subscription.
    pub explicit: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeDelivery {
    /// Index into the query's captured owner routes.
    pub owner: usize,
    /// Index into the captured recipient routes, or federation.
    pub recipient: Option<usize>,
    pub directed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeDecision {
    Silent,
    Unsubscribed,
    Unavailable { directed: Option<usize> },
    Available(Vec<ProbeDelivery>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeStatus {
    Silent,
    Unsubscribed,
    Unavailable,
    Available,
}

impl ProbeDecision {
    pub fn status(&self) -> ProbeStatus {
        match self {
            Self::Silent => ProbeStatus::Silent,
            Self::Unsubscribed => ProbeStatus::Unsubscribed,
            Self::Unavailable { .. } => ProbeStatus::Unavailable,
            Self::Available(_) => ProbeStatus::Available,
        }
    }
}

impl ProbeStatus {
    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Available, _) | (_, Self::Available) => Self::Available,
            (left, right) if left == right => left,
            _ => Self::Silent,
        }
    }
}

pub struct BroadcastQuery<'a> {
    pub actor: &'a RosterActor,
    pub expects_active: bool,
    pub local_domain: &'a str,
    pub candidates: &'a [BroadcastCandidate],
}

pub struct BroadcastCandidate {
    pub jid: String,
    pub account: Option<PresenceAccount>,
    pub routes: Vec<PresenceRoute>,
}

pub struct BroadcastFacts {
    pub jid: String,
    pub subscription: String,
    pub ask: Option<String>,
    pub account: Option<PresenceAccount>,
    pub recipients: Vec<PresenceRoute>,
}

pub trait PresenceDecisionReader: CommunicationPolicyReader {
    fn read_broadcast_facts(
        &self,
        query: BroadcastQuery<'_>,
    ) -> impl Future<Output = Result<Vec<BroadcastFacts>>> + Send;

    fn decide_probe(
        &self,
        query: ProbeQuery<'_>,
    ) -> impl Future<Output = Result<ProbeDecision>> + Send;
}
