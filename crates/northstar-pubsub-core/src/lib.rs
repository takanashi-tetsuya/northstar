#![forbid(unsafe_code)]

//! Core domain types and outcomes for PubSub / XEP-0060 / PEP flows.
//!
//! This crate intentionally contains no SQL, repository, or transport concerns.
//! It is meant to be used by application services that bind protocol input/output
//! and persistence adapters.

use chrono::{DateTime, Utc};
pub use northstar_xmpp_types::CanonicalJid;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct PubSubAccount {
    pub id: Uuid,
    pub username: String,
    pub auth_generation: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepNodeConfig {
    pub access_model: String,
    pub max_items: i32,
    pub persist_items: bool,
    pub send_last_published_item: String,
    pub deliver_notifications: bool,
    pub roster_groups_allowed: Vec<String>,
    pub access_whitelist: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct PepQuotas {
    pub max_nodes: i64,
    pub max_storage_bytes: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepCreateOutcome {
    Created,
    Conflict,
    QuotaExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepPublishOutcome {
    Published,
    Unauthorized,
    PreconditionFailed,
    MaxItemsExceeded,
    QuotaExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepSubscription {
    pub jid: String,
    pub subid: String,
}

#[derive(Clone, Debug)]
pub struct PepPresenceSubscription {
    pub owner_id: Uuid,
    pub owner_username: String,
    pub node: String,
}

#[derive(Clone, Debug)]
pub struct PepItem {
    pub item_id: String,
    pub payload: String,
    pub updated_at: DateTime<Utc>,
}

/// Authenticated principal and addressed PEP subscription identity.
pub struct PepSubscriptionActor<'a> {
    pub jid: &'a str,
    pub local_account: Option<&'a PubSubAccount>,
}

pub struct PepSubscribeWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub actor: PepSubscriptionActor<'a>,
    pub node: &'a str,
    pub subscriber_jid: &'a str,
    pub max_subscriptions: i64,
    pub requested_subid: &'a str,
}

pub struct PepUnsubscribeWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub actor: PepSubscriptionActor<'a>,
    pub node: &'a str,
    pub subscriber_jid: &'a str,
    pub subid: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct PepSubscribeSnapshot {
    pub owner_id: Uuid,
    pub owner_bare_jid: String,
    pub node: String,
    pub subscriber_jid: String,
    pub subscriber_account_id: Option<Uuid>,
    pub local_domain: String,
    pub last_item: Option<PepItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PepSubscribeOutcome {
    Subscribed(PepSubscription),
    NotFound,
    Forbidden,
    NotAuthorized(String),
    LimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PepUnsubscribeOutcome {
    /// `None` is an idempotent retry after the exact subscription disappeared.
    Unsubscribed(Option<String>),
    NotFound,
    Forbidden,
    InvalidSubid,
}

pub struct PepProfileWrite<'a> {
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub requested: &'a PepNodeConfig,
    pub enforce_preconditions: bool,
    pub items: &'a [(&'a str, &'a str)],
    pub max_nodes: i64,
    pub max_storage_bytes: i64,
}

/// Generic PEP publication intent. Durable authorization is intentionally not
/// part of this command: the service derives it from the locked node, roster,
/// block policy and explicit subscriptions in the write transaction.
pub struct PepPublishWrite<'a> {
    pub user_id: Uuid,
    pub username: &'a str,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub requested: &'a PepNodeConfig,
    pub enforce_preconditions: bool,
    pub items: &'a [(&'a str, &'a str)],
    pub quotas: PepQuotas,
}

/// Exact durable PEP audience captured while every policy input is locked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepAudienceSnapshot {
    pub owner_bare_jid: String,
    pub roster_jids: Vec<String>,
    pub explicit_jids: Vec<String>,
}

impl PepAudienceSnapshot {
    pub fn authorizes_routed_jid(&self, recipient: &str) -> bool {
        let Ok(recipient) = CanonicalJid::parse(recipient) else {
            return false;
        };
        let full = recipient.to_string();
        let bare = recipient.bare();
        bare == self.owner_bare_jid
            || self.roster_jids.iter().any(|jid| jid == &bare)
            || self.explicit_jids.iter().any(|jid| {
                CanonicalJid::parse(jid).is_ok_and(|explicit| {
                    if explicit.resourcepart().is_some() {
                        explicit.to_string() == full
                    } else {
                        explicit.bare() == bare
                    }
                })
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PepDirectStateTransition {
    Subscription {
        recipient_jid: String,
        subid: String,
        state: String,
    },
    Affiliation {
        recipient_jid: String,
        affiliation: String,
    },
}

impl PepDirectStateTransition {
    pub fn recipient_jid(&self) -> &str {
        match self {
            Self::Subscription { recipient_jid, .. } | Self::Affiliation { recipient_jid, .. } => {
                recipient_jid
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepDirectStateSnapshot {
    pub owner_bare_jid: String,
    pub node: String,
    pub transitions: Vec<PepDirectStateTransition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepOwnerMutationOutcome {
    Applied(u64),
    NotFound,
    Forbidden,
    Stale,
    NotSubscribed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepBookmarkMutationOutcome {
    Stored,
    ConcurrentChange,
    ResourceConstraint,
    Forbidden,
}

#[derive(Clone, Debug)]
pub struct PubSubNode {
    pub id: Uuid,
    pub node: String,
    pub creator_jid: String,
    pub access_model: String,
    pub publish_model: String,
    pub max_items: i32,
    pub title: Option<String>,
    pub description: Option<String>,
    pub deliver_payloads: bool,
    pub notify_delete: bool,
    pub notify_retract: bool,
    pub persist_items: bool,
    pub send_last_published_item: String,
    pub node_type: String,
    pub deliver_notifications: bool,
    pub notify_config: bool,
    pub notify_sub: bool,
    pub language: Option<String>,
    pub payload_type: Option<String>,
    pub max_payload_size: i32,
    pub children_max: i32,
    pub children_association_policy: String,
    pub children_association_whitelist: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl PubSubNode {
    pub fn config(&self) -> PubSubNodeConfig {
        PubSubNodeConfig {
            access_model: self.access_model.clone(),
            publish_model: self.publish_model.clone(),
            max_items: self.max_items,
            title: self.title.clone(),
            description: self.description.clone(),
            deliver_payloads: self.deliver_payloads,
            notify_delete: self.notify_delete,
            notify_retract: self.notify_retract,
            persist_items: self.persist_items,
            send_last_published_item: self.send_last_published_item.clone(),
            node_type: self.node_type.clone(),
            deliver_notifications: self.deliver_notifications,
            notify_config: self.notify_config,
            notify_sub: self.notify_sub,
            language: self.language.clone(),
            payload_type: self.payload_type.clone(),
            max_payload_size: self.max_payload_size,
            children_max: self.children_max,
            children_association_policy: self.children_association_policy.clone(),
            children_association_whitelist: self.children_association_whitelist.clone(),
            collections: Vec::new(),
            children: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubSubNodeConfig {
    pub access_model: String,
    pub publish_model: String,
    pub max_items: i32,
    pub title: Option<String>,
    pub description: Option<String>,
    pub deliver_payloads: bool,
    pub notify_delete: bool,
    pub notify_retract: bool,
    pub persist_items: bool,
    pub send_last_published_item: String,
    pub node_type: String,
    pub deliver_notifications: bool,
    pub notify_config: bool,
    pub notify_sub: bool,
    pub language: Option<String>,
    pub payload_type: Option<String>,
    pub max_payload_size: i32,
    pub children_max: i32,
    pub children_association_policy: String,
    pub children_association_whitelist: Vec<String>,
    pub collections: Vec<String>,
    pub children: Vec<String>,
}

impl Default for PubSubNodeConfig {
    fn default() -> Self {
        Self {
            access_model: "open".to_owned(),
            publish_model: "publishers".to_owned(),
            max_items: 100,
            title: None,
            description: None,
            deliver_payloads: true,
            notify_delete: true,
            notify_retract: true,
            persist_items: true,
            send_last_published_item: "on_sub_and_presence".to_owned(),
            node_type: "leaf".to_owned(),
            deliver_notifications: true,
            notify_config: true,
            notify_sub: true,
            language: None,
            payload_type: None,
            max_payload_size: 1_048_576,
            children_max: 1_000,
            children_association_policy: "owner".to_owned(),
            children_association_whitelist: Vec::new(),
            collections: Vec::new(),
            children: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PubSubItem {
    pub item_id: String,
    pub xml_payload: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct CollectionVisibleItem {
    pub node: String,
    pub xml_payload: String,
}

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
    pub fn is_active(&self) -> bool {
        self.state == "subscribed" && self.expire.is_none_or(|expire| expire > Utc::now())
    }

    pub fn is_expired(&self) -> bool {
        self.expire.is_some_and(|expire| expire <= Utc::now())
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

#[derive(Clone, Debug)]
pub struct PubSubAffiliation {
    pub node: String,
    pub jid: String,
    pub affiliation: String,
}

#[derive(Clone, Debug)]
pub struct PubSubDiscoNode {
    pub node: String,
    pub title: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionAuthorizationOutcome {
    Applied,
    NotFound,
    Forbidden,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubOutboxSource {
    PubSub,
    Pep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubOutboxDeliveryKind {
    PubSubChildren,
    PubSubDigest,
    PubSubDirect,
    PepStanza,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetractItemsOutcome {
    Retracted,
    NotFound,
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

pub struct PubSubPublishWrite<'a> {
    pub publisher_jid: &'a str,
    pub node: &'a str,
    pub items: &'a [(String, String)],
    pub publish_options: Option<&'a PubSubNodeConfig>,
    pub max_storage_bytes_per_owner: i64,
    pub max_nodes_per_owner: i64,
}

pub struct PubSubSubscribeWrite<'a> {
    pub requester: &'a str,
    pub subscriber_jid: &'a str,
    pub node: &'a str,
    pub options: Option<&'a PubSubSubscriptionOptions>,
    pub max_subscriptions: i64,
}

pub struct PubSubUnsubscribeWrite<'a> {
    pub requester: &'a str,
    pub subscriber_jid: &'a str,
    pub node: &'a str,
    pub subid: Option<&'a str>,
}

pub struct PubSubRetractWrite<'a> {
    pub requester: &'a str,
    pub node: &'a str,
    pub item_ids: &'a [String],
    pub force_notification: bool,
}

pub struct PubSubCreateNodeWrite<'a> {
    pub creator_jid: &'a str,
    pub node: &'a str,
    pub config: &'a PubSubNodeConfig,
    pub max_nodes_per_owner: i64,
}

pub struct PubSubDeleteNodeWrite<'a> {
    pub requester: &'a str,
    pub node: &'a str,
    pub redirect: Option<&'a str>,
}

pub struct PubSubPurgeNodeWrite<'a> {
    pub requester: &'a str,
    pub node: &'a str,
}

pub struct PubSubConfigureNodeWrite<'a> {
    pub requester: &'a str,
    pub node: &'a str,
    pub expected: &'a PubSubNodeConfig,
    pub config: &'a PubSubNodeConfig,
}

pub struct PubSubSetSubscriptionsWrite<'a> {
    pub requester: &'a str,
    pub node: &'a str,
    pub changes: &'a [(String, String, Option<String>)],
}

pub struct PubSubSetAffiliationsWrite<'a> {
    pub requester: &'a str,
    pub node: &'a str,
    pub changes: &'a [(String, String)],
}

pub struct PepRetractWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub item_ids: &'a [String],
    pub notify: bool,
}

pub struct PepDeleteNodeWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
}

pub struct PepPurgeNodeWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
}

pub struct PepConfigureNodeWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub expected: &'a PepNodeConfig,
    pub config: &'a PepNodeConfig,
}

pub struct PepSetAffiliationsWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub expected: &'a PepNodeConfig,
    pub changes: &'a [(String, String)],
}


