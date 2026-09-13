//! Capability-free RFC 6121 roster domain entities, subscription state machines,
//! and snapshot models.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use uuid::Uuid;

/// One versioned roster item modification or deletion.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RosterChange {
    pub version: i64,
    pub contact_jid: String,
    pub display_name: Option<String>,
    pub subscription: Option<String>,
    pub ask: Option<String>,
    pub groups: Vec<String>,
    pub approved: bool,
    pub removed: bool,
}

/// One XEP-0237 response view, including optional XEP-0405 annotations.
/// Every field is read from one snapshot so a response can never combine an
/// older roster version with newer PAM state.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RosterReadSnapshot {
    pub version: i64,
    pub items: Vec<RosterChange>,
    /// `Some` is a valid versioned delta (including an empty delta). `None`
    /// requires a complete roster response.
    pub changes: Option<Vec<RosterChange>>,
    pub mix_participants: HashMap<String, String>,
}

/// Minimal identity of a local roster contact account.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LocalRosterContact {
    pub id: Uuid,
    pub username: String,
    pub auth_generation: i64,
}

/// The committed effects of removing one RFC 6121 roster item.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RosterRemovalTransition {
    pub owner_change: RosterChange,
    pub contact_change: Option<RosterChange>,
    /// Exact account incarnation resolved and locked by the removal transaction.
    pub local_contact: Option<LocalRosterContact>,
    pub send_unsubscribe: bool,
    pub send_unsubscribed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedRosterRemoval {
    Unauthorized,
    Missing,
    Removed(Box<RosterRemovalTransition>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RosterAuthorization<T> {
    Authorized(T),
    Unauthorized,
}

/// RFC 6121 Subscription State.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SubscriptionType {
    None,
    To,
    From,
    Both,
    Remove,
}

impl SubscriptionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::To => "to",
            Self::From => "from",
            Self::Both => "both",
            Self::Remove => "remove",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "to" => Some(Self::To),
            "from" => Some(Self::From),
            "both" => Some(Self::Both),
            "remove" => Some(Self::Remove),
            _ => None,
        }
    }
}

/// RFC 6121 Pending Subscription Ask State.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AskType {
    None,
    Subscribe,
}

impl AskType {
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Subscribe => Some("subscribe"),
        }
    }

    pub fn parse(s: Option<&str>) -> Self {
        match s {
            Some("subscribe") => Self::Subscribe,
            _ => Self::None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPresenceEffect {
    Forward,
    AutoApproved,
    Suppressed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPresenceTransition {
    pub effect: LocalPresenceEffect,
    pub actor_subscription: String,
    pub actor_changed: bool,
    pub target_changed: bool,
    pub actor_change: Option<RosterChange>,
    pub target_change: Option<RosterChange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresenceAccount {
    pub id: Uuid,
    pub username: String,
    pub auth_generation: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresencePolicyDenial {
    Blocking,
    Privacy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedLocalPresence {
    pub actor: PresenceAccount,
    pub target: PresenceAccount,
    pub transition: LocalPresenceTransition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedLocalPresenceTransition {
    Unauthorized,
    PolicyDenied(PresencePolicyDenial),
    Missing,
    Transition(Box<AuthorizedLocalPresence>),
}

/// Pure evaluation of RFC 6121 outbound presence subscription request.
/// Returns `(new_subscription, new_ask, should_send_outbound)`.
pub fn evaluate_outbound_subscribe(
    current: SubscriptionType,
    _ask: AskType,
) -> (SubscriptionType, AskType, bool) {
    match current {
        SubscriptionType::None => (SubscriptionType::None, AskType::Subscribe, true),
        SubscriptionType::To => (SubscriptionType::To, AskType::None, false),
        SubscriptionType::From => (SubscriptionType::From, AskType::Subscribe, true),
        SubscriptionType::Both => (SubscriptionType::Both, AskType::None, false),
        SubscriptionType::Remove => (SubscriptionType::None, AskType::Subscribe, true),
    }
}

/// Pure evaluation of RFC 6121 outbound subscription cancellation (unsubscribe).
/// Returns `(new_subscription, new_ask, should_send_outbound)`.
pub fn evaluate_outbound_unsubscribe(
    current: SubscriptionType,
    _ask: AskType,
) -> (SubscriptionType, AskType, bool) {
    match current {
        SubscriptionType::None => (SubscriptionType::None, AskType::None, false),
        SubscriptionType::To => (SubscriptionType::None, AskType::None, true),
        SubscriptionType::From => (SubscriptionType::From, AskType::None, false),
        SubscriptionType::Both => (SubscriptionType::From, AskType::None, true),
        SubscriptionType::Remove => (SubscriptionType::None, AskType::None, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_type_roundtrip() {
        for sub in [
            SubscriptionType::None,
            SubscriptionType::To,
            SubscriptionType::From,
            SubscriptionType::Both,
            SubscriptionType::Remove,
        ] {
            assert_eq!(SubscriptionType::parse(sub.as_str()), Some(sub));
        }
        assert_eq!(SubscriptionType::parse("unknown"), None);
    }

    #[test]
    fn ask_type_roundtrip() {
        assert_eq!(AskType::parse(None), AskType::None);
        assert_eq!(AskType::parse(Some("subscribe")), AskType::Subscribe);
        assert_eq!(AskType::parse(Some("other")), AskType::None);
        assert_eq!(AskType::None.as_str(), None);
        assert_eq!(AskType::Subscribe.as_str(), Some("subscribe"));
    }

    #[test]
    fn outbound_subscribe_transitions() {
        let (sub, ask, send) = evaluate_outbound_subscribe(SubscriptionType::None, AskType::None);
        assert_eq!(sub, SubscriptionType::None);
        assert_eq!(ask, AskType::Subscribe);
        assert!(send);

        let (sub, ask, send) = evaluate_outbound_subscribe(SubscriptionType::To, AskType::None);
        assert_eq!(sub, SubscriptionType::To);
        assert_eq!(ask, AskType::None);
        assert!(!send);

        let (sub, ask, send) = evaluate_outbound_subscribe(SubscriptionType::From, AskType::None);
        assert_eq!(sub, SubscriptionType::From);
        assert_eq!(ask, AskType::Subscribe);
        assert!(send);

        let (sub, ask, send) = evaluate_outbound_subscribe(SubscriptionType::Both, AskType::None);
        assert_eq!(sub, SubscriptionType::Both);
        assert_eq!(ask, AskType::None);
        assert!(!send);
    }

    #[test]
    fn outbound_unsubscribe_transitions() {
        let (sub, ask, send) = evaluate_outbound_unsubscribe(SubscriptionType::Both, AskType::None);
        assert_eq!(sub, SubscriptionType::From);
        assert_eq!(ask, AskType::None);
        assert!(send);

        let (sub, ask, send) = evaluate_outbound_unsubscribe(SubscriptionType::To, AskType::None);
        assert_eq!(sub, SubscriptionType::None);
        assert_eq!(ask, AskType::None);
        assert!(send);

        let (sub, ask, send) = evaluate_outbound_unsubscribe(SubscriptionType::None, AskType::None);
        assert_eq!(sub, SubscriptionType::None);
        assert_eq!(ask, AskType::None);
        assert!(!send);
    }
}
