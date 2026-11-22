//! PubSub row types and repository outcomes.

use northstar_time::{DateTime, Utc};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Serialize, Clone)]
pub struct PubSubItem {
    pub item_id: String,
    pub publisher_jid: String,
    pub xml_payload: String,
    pub created_at: DateTime<Utc>,
}

/// One item from an ACL-filtered descendant leaf of a collection. The
/// database returns these in `(node ASC, item recency DESC)` order from one
/// statement snapshot so callers cannot accidentally split graph traversal,
/// authorization and payload extraction into a TOCTOU sequence.
#[derive(Debug, Serialize)]
pub struct CollectionVisibleItem {
    pub node: String,
    pub xml_payload: String,
}

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug)]
pub struct PubSubSubscriptionOptions {
    pub deliver: bool,
    pub digest: bool,
    pub digest_frequency: i32,
    pub expire: Option<DateTime<Utc>>,
    pub include_body: bool,
    pub show_values: Vec<String>,
    pub subscription_type: String,
    /// `None` is the XEP-0248 value `all`.
    pub subscription_depth: Option<i32>,
}

impl PubSubSubscriptionOptions {
    #[cfg(any(test, feature = "test-support"))]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionUpdateOutcome {
    Updated,
    NotFound,
    NotAssociated,
    NotCollection,
    Forbidden,
    LimitExceeded,
    DepthExceeded,
    Cycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubConfigOutcome {
    Updated,
    Conflict,
    NotFound,
    InvalidOptions,
    Forbidden,
    LimitExceeded,
    Cycle,
}

#[derive(Clone, Debug)]
pub struct PubSubNotificationDelivery {
    pub subscription_node_id: Uuid,
    pub subscription: PubSubSubscription,
    pub collection: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PubSubAffiliation {
    pub node: String,
    pub jid: String,
    pub affiliation: String,
}

pub(super) fn row_to_affiliation(row: &sqlx::postgres::PgRow) -> PubSubAffiliation {
    PubSubAffiliation {
        node: row.get("node"),
        jid: row.get("jid"),
        affiliation: row.get("affiliation"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateNodeOutcome {
    Created(Uuid),
    Conflict,
    QuotaExceeded,
    InvalidOptions,
    Forbidden,
    CollectionLimitExceeded,
    Cycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishItemsOutcome {
    Published,
    Conflict,
    QuotaExceeded,
    Forbidden,
    PreconditionFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetractItemsOutcome {
    Retracted,
    NotFound,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetAffiliationsOutcome {
    Updated {
        /// Active or pending subscriptions cancelled by an `outcast`
        /// affiliation change. The SubID is retained for the mandatory
        /// post-commit state-change notification.
        revoked_subscriptions: Vec<(String, String)>,
        /// Pending subscriptions automatically approved when their bare JID
        /// becomes an owner or publisher (XEP-0060 section 8.7.4).
        approved_subscriptions: Vec<(String, String)>,
    },
    LastOwner,
    NotFound,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetSubscriptionsOutcome {
    /// Canonical JID, new state and stable SubID for each actual transition.
    Updated(Vec<(String, String, String)>),
    LimitExceeded,
    InvalidSubid,
    NotFound,
    Forbidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerMutationOutcome {
    Applied,
    NotFound,
    Forbidden,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionAuthorizationOutcome {
    Applied,
    NotFound,
    Forbidden,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsubscribeOutcome {
    Unsubscribed,
    NotFound,
    InvalidSubid,
    Forbidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionOptionsOutcome {
    Updated,
    NotFound,
    InvalidSubid,
    InvalidOptions,
    Forbidden,
}

#[derive(Clone, Debug)]
pub enum SubscribeOutcome {
    Subscribed(PubSubSubscription),
    LimitExceeded,
    NotFound,
    Forbidden,
    ClosedNode,
    PreconditionFailed,
    InvalidOptions,
}
