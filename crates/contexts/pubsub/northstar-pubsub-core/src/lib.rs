#![forbid(unsafe_code)]

//! Core domain types and outcomes for PubSub / XEP-0060 / PEP flows.
//!
//! This crate intentionally contains no SQL, repository, or transport concerns.
//! It is meant to be used by application services that bind protocol input/output
//! and persistence adapters.

#[cfg(test)]
use northstar_time::{DateTime, Utc};
pub use northstar_xmpp_types::CanonicalJid;
use uuid::Uuid;

mod item_access;
mod pep_form_policy;
mod pep_policy;
pub mod telemetry;
pub use pep_form_policy::*;
pub use pep_policy::*;

pub use item_access::item_retrieval_access;
mod authority;
mod clock;
pub use authority::*;
pub use clock::*;

mod node;
mod outcomes;
mod owner_preflight;
mod pep;
mod replay;
mod subscription;
mod writes;

pub use node::*;
pub use outcomes::*;
pub use owner_preflight::PubSubOwnerPreflight;
pub use pep::*;
pub use replay::*;
pub use subscription::*;
pub use writes::*;

#[cfg(test)]
mod subscription_tests {
    use super::*;

    #[test]
    fn subscription_expires_at_its_deadline() {
        let deadline = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let subscription = PubSubSubscription {
            node: "updates".into(),
            jid: "reader@example.org".into(),
            state: "subscribed".into(),
            subid: "s1".into(),
            deliver: true,
            digest: false,
            digest_frequency: 0,
            expire: Some(deadline),
            include_body: false,
            show_values: Vec::new(),
            subscription_type: "items".into(),
            subscription_depth: Some(1),
        };
        let before = deadline - northstar_time::Duration::nanoseconds(1);
        assert!(subscription.is_active_at(before));
        assert!(!subscription.is_expired_at(before));
        assert!(!subscription.is_active_at(deadline));
        assert!(subscription.is_expired_at(deadline));
    }

    #[test]
    fn subscribe_policy_keeps_affiliation_and_access_boundaries() {
        use PubSubSubscribePolicy::*;
        for (access, affiliation, expected) in [
            ("open", None, Subscribed),
            ("open", Some("publish-only"), Forbidden),
            ("open", Some("outcast"), Forbidden),
            ("whitelist", Some("member"), Subscribed),
            ("whitelist", None, ClosedNode),
            ("authorize", Some("publisher"), Subscribed),
            ("authorize", None, Pending),
            ("unknown", Some("owner"), Forbidden),
        ] {
            assert_eq!(pubsub_subscribe_policy(access, affiliation), expected);
        }
    }
}

#[cfg(test)]
mod options_policy_tests {
    use super::*;

    #[test]
    fn locked_node_policy_rejects_stale_type_and_payload_options() {
        let atom = "http://www.w3.org/2005/Atom";
        let mut options = PubSubSubscriptionOptions::for_node_type("leaf");
        options.include_body = true;
        assert!(subscription_options_match_node_policy(
            "leaf",
            Some(atom),
            Some(1),
            &options,
        ));
        assert!(!subscription_options_match_node_policy(
            "leaf",
            None,
            Some(1),
            &options,
        ));

        options.include_body = false;
        options.subscription_type = "nodes".to_owned();
        assert!(subscription_options_match_node_policy(
            "collection",
            None,
            Some(1),
            &options,
        ));
        assert!(!subscription_options_match_node_policy(
            "leaf",
            None,
            Some(1),
            &options,
        ));
        options.subscription_type = "items".to_owned();
        options.subscription_depth = Some(2);
        assert!(!subscription_options_match_node_policy(
            "leaf",
            None,
            Some(1),
            &options,
        ));
    }
}

pub mod outbox;
pub use outbox::*;

#[derive(Clone, Debug)]
pub struct PubSubNotificationDelivery {
    pub subscription_node_id: Uuid,
    pub subscription: PubSubSubscription,
    pub collection: Option<String>,
}

/// Contact JID, display name, subscription state and pending request.
pub type PubSubRosterEntry = (String, Option<String>, String, Option<String>);
