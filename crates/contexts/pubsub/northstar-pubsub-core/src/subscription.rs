//! PubSub subscription state and policy.

use northstar_time::{DateTime, Utc};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubSubSubscription {
    pub node: String,
    pub jid: String,
    pub state: String,
    pub subid: String,
    pub deliver: bool,
    pub digest: bool,
    pub digest_frequency: i32,
    pub expire: Option<DateTime<Utc>>,
    pub include_body: bool,
    pub show_values: Vec<String>,
    pub subscription_type: String,
    pub subscription_depth: Option<i32>,
}

impl PubSubSubscription {
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.state == "subscribed" && self.expire.is_none_or(|expire| expire > now)
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expire.is_some_and(|expire| expire <= now)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubSubscribePolicy {
    Subscribed,
    Pending,
    ClosedNode,
    Forbidden,
}

pub fn pubsub_subscribe_policy(
    access_model: &str,
    affiliation: Option<&str>,
) -> PubSubSubscribePolicy {
    use PubSubSubscribePolicy::*;
    if matches!(affiliation, Some("outcast" | "publish-only")) {
        return Forbidden;
    }
    let affiliated = matches!(affiliation, Some("owner" | "publisher" | "member"));
    match access_model {
        "open" => Subscribed,
        "whitelist" if affiliated => Subscribed,
        "whitelist" => ClosedNode,
        "authorize" if affiliated => Subscribed,
        "authorize" => Pending,
        _ => Forbidden,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubSubSubscriptionOptions {
    pub deliver: bool,
    pub digest: bool,
    pub digest_frequency: i32,
    pub expire: Option<DateTime<Utc>>,
    pub include_body: bool,
    pub show_values: Vec<String>,
    pub subscription_type: String,
    pub subscription_depth: Option<i32>,
}

impl PubSubSubscriptionOptions {
    pub fn for_node_type(node_type: &str) -> Self {
        Self {
            deliver: true,
            digest: false,
            digest_frequency: 86_400_000,
            expire: None,
            include_body: false,
            show_values: vec![
                "away".to_owned(),
                "chat".to_owned(),
                "dnd".to_owned(),
                "online".to_owned(),
                "xa".to_owned(),
            ],
            subscription_type: if node_type == "collection" {
                "nodes".to_owned()
            } else {
                "items".to_owned()
            },
            subscription_depth: Some(1),
        }
    }
}

/// Recheck the node-dependent part of an options form after locking the node.
/// A leaf may retain a legacy depth value when the form does not change it;
/// clients cannot set a new depth on a leaf.
pub fn subscription_options_match_node_policy(
    node_type: &str,
    payload_type: Option<&str>,
    current_depth: Option<i32>,
    options: &PubSubSubscriptionOptions,
) -> bool {
    if options.include_body && payload_type != Some("http://www.w3.org/2005/Atom") {
        return false;
    }
    match node_type {
        "collection" => {
            matches!(
                options.subscription_type.as_str(),
                "items" | "nodes" | "all"
            ) && options.subscription_depth.is_none_or(|depth| depth >= 0)
        }
        "leaf" => {
            options.subscription_type == "items" && options.subscription_depth == current_depth
        }
        _ => false,
    }
}
