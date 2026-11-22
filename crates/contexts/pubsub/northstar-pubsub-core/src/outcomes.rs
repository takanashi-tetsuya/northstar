//! PubSub operation outcomes and outbox snapshots.

use crate::PubSubSubscription;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionAuthorizationOutcome {
    Applied,
    NotFound,
    Forbidden,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepOutboxDropReason {
    UnverifiableIdentity,
    SenderUnavailable,
    RecipientUnavailable,
    Blocked,
    PrivacyDenied,
    NodeAccessRevoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepOutboxAuthorizationOutcome {
    Deliver,
    Drop(PepOutboxDropReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubOutboxFailureDisposition {
    Retry,
    DeadLettered,
    LeaseLost,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PubSubOutboxSnapshot {
    pub pending_rows: i64,
    pub pending_bytes: i64,
    pub leased_rows: i64,
    pub due_rows: i64,
    pub dead_letter_rows: i64,
}

#[derive(Clone, Debug)]
pub struct DuePubSubDigest {
    pub ids: Vec<Uuid>,
    pub subscription_node_id: Uuid,
    pub subscriber_jid: String,
    pub event_xml: Vec<String>,
    pub show_values: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateNodeOutcome {
    Created,
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
    Rejected(PublishPolicyRejection),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishPolicyRejection {
    PreconditionNotMet,
    NotLeafNode,
    MaxItemsExceeded,
    ItemRequired,
    ItemForbidden,
    PayloadRequired,
    PayloadTooBig,
    InvalidPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutoCreatePublishOutcome {
    Published,
    /// The transaction found an existing node and made no changes.
    NodeExists,
    /// Creation failed and the transaction rolled back.
    Create(CreateNodeOutcome),
    /// Publication failed and the transaction rolled back, including creation.
    Publish(PublishItemsOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetractItemsOutcome {
    Retracted,
    NotFound,
    NotLeafNode,
    NotPersistent,
    Forbidden,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetSubscriptionsOutcome {
    Updated(Vec<(String, String, String)>),
    LimitExceeded,
    InvalidSubid,
    NotFound,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetAffiliationsOutcome {
    Updated {
        revoked_subscriptions: Vec<(String, String)>,
        approved_subscriptions: Vec<(String, String)>,
    },
    LastOwner,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PubSubPublishOutcome {
    Published { item_ids: Vec<String> },
    MissingNode,
    PreconditionNotMet,
    NotLeafNode,
    Forbidden,
    MaxItemsExceeded,
    ItemRequired,
    ItemForbidden,
    PayloadRequired,
    PayloadTooBig,
    InvalidPayload,
    QuotaExceeded,
    Conflict,
}

impl From<PublishPolicyRejection> for PubSubPublishOutcome {
    fn from(rejection: PublishPolicyRejection) -> Self {
        match rejection {
            PublishPolicyRejection::PreconditionNotMet => Self::PreconditionNotMet,
            PublishPolicyRejection::NotLeafNode => Self::NotLeafNode,
            PublishPolicyRejection::MaxItemsExceeded => Self::MaxItemsExceeded,
            PublishPolicyRejection::ItemRequired => Self::ItemRequired,
            PublishPolicyRejection::ItemForbidden => Self::ItemForbidden,
            PublishPolicyRejection::PayloadRequired => Self::PayloadRequired,
            PublishPolicyRejection::PayloadTooBig => Self::PayloadTooBig,
            PublishPolicyRejection::InvalidPayload => Self::InvalidPayload,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PubSubSubscribeOutcome {
    Subscribed(PubSubSubscription),
    ExistingActive(PubSubSubscription),
    PendingSubscription,
    LimitExceeded,
    NotFound,
    Forbidden,
    ClosedNode,
    PreconditionFailed,
    InvalidOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PubSubUnsubscribeOutcome {
    Unsubscribed { subid: Option<String> },
    NotFound,
    NotSubscribed,
    InvalidSubid,
    Forbidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubRetractOutcome {
    Retracted,
    NotFound,
    ItemNotFound,
    Forbidden,
    NotLeafNode,
    NotPersistent,
}
