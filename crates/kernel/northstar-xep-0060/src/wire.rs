//! Request, response, and event wire models for XEP-0060 Publish-Subscribe stanzas.

use crate::config::{NodeConfig, SubscriptionOptions};
use crate::models::{Affiliation, CollectionAction, NodeType, SubscriptionState};
use crate::rsm::{RsmRequest, RsmResponse};

// Entity Request / Response Models

/// `pubsub` -> `create` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateNodeRequest {
    pub node: Option<String>,
    pub configure: Option<NodeConfig>,
}

/// `pubsub` -> `create` response payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateNodeResponse {
    pub node: String,
}

/// One published item in a publication request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishItemWire {
    pub id: String,
    pub payload_xml: String,
}

/// `pubsub` -> `publish` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishRequest {
    pub node: String,
    pub items: Vec<PublishItemWire>,
    pub publish_options: Option<NodeConfig>,
}

/// `pubsub` -> `publish` response payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishResponse {
    pub node: String,
    pub item_ids: Vec<String>,
}

/// `pubsub` -> `retract` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetractRequest {
    pub node: String,
    pub item_ids: Vec<String>,
    pub notify: bool,
}

/// `pubsub` -> `subscribe` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribeRequest {
    pub node: String,
    pub jid: String,
    pub options: Option<SubscriptionOptions>,
}

/// `pubsub` -> `subscribe` response payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribeResponse {
    pub node: String,
    pub jid: String,
    pub state: SubscriptionState,
    pub subid: Option<String>,
    pub expiry: Option<String>,
}

/// `pubsub` -> `unsubscribe` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsubscribeRequest {
    pub node: String,
    pub jid: String,
    pub subid: Option<String>,
}

/// `pubsub` -> `unsubscribe` response payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsubscribeResponse {
    pub node: String,
    pub jid: String,
    pub subid: Option<String>,
}

/// `pubsub` -> `options` (get) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetOptionsRequest {
    pub node: String,
    pub jid: String,
    pub subid: Option<String>,
}

/// `pubsub` -> `options` (get) response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetOptionsResponse {
    pub node: String,
    pub jid: String,
    pub subid: Option<String>,
    pub options: SubscriptionOptions,
}

/// `pubsub` -> `options` (set) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetOptionsRequest {
    pub node: String,
    pub jid: String,
    pub subid: Option<String>,
    pub options: Option<SubscriptionOptions>,
    pub is_cancel: bool,
}

/// `pubsub` -> `default` (get) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetDefaultOptionsRequest {
    pub node: Option<String>,
}

/// `pubsub` -> `default` (get) response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetDefaultOptionsResponse {
    pub node: Option<String>,
    pub options: SubscriptionOptions,
}

/// `pubsub` -> `items` (get) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetItemsRequest {
    pub node: String,
    pub max_items: Option<u32>,
    pub subid: Option<String>,
    pub item_ids: Vec<String>,
    pub rsm: Option<RsmRequest>,
}

/// One item entry returned from item retrieval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemEntryWire {
    pub id: String,
    pub xml_payload: String,
}

/// `pubsub` -> `items` response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetItemsResponse {
    pub node: String,
    pub items: Vec<ItemEntryWire>,
    pub rsm: Option<RsmResponse>,
}

/// `pubsub` -> `subscriptions` (get) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetSubscriptionsRequest {
    pub node: Option<String>,
}

/// One subscription descriptor entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionEntryWire {
    pub node: String,
    pub jid: String,
    pub state: SubscriptionState,
    pub subid: Option<String>,
    pub expiry: Option<String>,
}

/// `pubsub` -> `subscriptions` response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetSubscriptionsResponse {
    pub node: Option<String>,
    pub subscriptions: Vec<SubscriptionEntryWire>,
}

/// `pubsub` -> `affiliations` (get) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetAffiliationsRequest {
    pub node: Option<String>,
}

/// One affiliation descriptor entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffiliationEntryWire {
    pub node: String,
    pub affiliation: Affiliation,
}

/// `pubsub` -> `affiliations` response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetAffiliationsResponse {
    pub affiliations: Vec<AffiliationEntryWire>,
}

// Owner Request / Response Models

/// `pubsub#owner` -> `configure` (get) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerGetConfigureRequest {
    pub node: String,
}

/// `pubsub#owner` -> `configure` (get) response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerGetConfigureResponse {
    pub node: String,
    pub config: NodeConfig,
}

/// `pubsub#owner` -> `configure` (set) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSetConfigureRequest {
    pub node: String,
    pub config: Option<NodeConfig>,
    pub is_cancel: bool,
}

/// `pubsub#owner` -> `default` (get) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerGetDefaultRequest {
    pub node_type: Option<NodeType>,
}

/// `pubsub#owner` -> `default` (get) response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerGetDefaultResponse {
    pub config: NodeConfig,
}

/// `pubsub#owner` -> `delete` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerDeleteNodeRequest {
    pub node: String,
    pub redirect: Option<String>,
}

/// `pubsub#owner` -> `purge` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerPurgeNodeRequest {
    pub node: String,
}

/// `pubsub#owner` -> `subscriptions` (get) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerGetSubscriptionsRequest {
    pub node: String,
}

/// One owner subscription entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSubscriptionEntryWire {
    pub jid: String,
    pub state: SubscriptionState,
    pub subid: String,
    pub expiry: Option<String>,
}

/// `pubsub#owner` -> `subscriptions` (get) response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerGetSubscriptionsResponse {
    pub node: String,
    pub subscriptions: Vec<OwnerSubscriptionEntryWire>,
}

/// One subscription change entry in owner subscriptions set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSubscriptionChangeWire {
    pub jid: String,
    pub state: Option<SubscriptionState>,
    pub subid: Option<String>,
}

/// `pubsub#owner` -> `subscriptions` (set) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSetSubscriptionsRequest {
    pub node: String,
    pub changes: Vec<OwnerSubscriptionChangeWire>,
}

/// `pubsub#owner` -> `affiliations` (get) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerGetAffiliationsRequest {
    pub node: String,
}

/// One owner affiliation entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerAffiliationEntryWire {
    pub jid: String,
    pub affiliation: Affiliation,
}

/// `pubsub#owner` -> `affiliations` (get) response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerGetAffiliationsResponse {
    pub node: String,
    pub affiliations: Vec<OwnerAffiliationEntryWire>,
}

/// One affiliation change in owner affiliations set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerAffiliationChangeWire {
    pub jid: String,
    pub affiliation: Option<Affiliation>,
}

/// `pubsub#owner` -> `affiliations` (set) request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSetAffiliationsRequest {
    pub node: String,
    pub changes: Vec<OwnerAffiliationChangeWire>,
}

/// `pubsub#owner` -> `collection` request (associate / dissociate child node).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerCollectionRequest {
    pub node: String,
    pub action: CollectionAction,
}

// Event & Authorization Wire Models

/// One published item in an event notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventItemWire {
    pub id: String,
    pub payload_xml: Option<String>,
}

/// Event notification representation (`http://jabber.org/protocol/pubsub#event`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventPayload {
    Items {
        node: String,
        items: Vec<EventItemWire>,
        retract: Vec<String>,
    },
    Delete {
        node: String,
        redirect: Option<String>,
    },
    Purge {
        node: String,
    },
    Configuration {
        node: String,
        form_xml: Option<String>,
    },
    Subscription {
        node: String,
        jid: String,
        state: SubscriptionState,
        subid: Option<String>,
        expiry: Option<String>,
    },
}

/// XEP-0060 Subscription Authorization Form Response (`pubsub#subscribe_authorization`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionAuthResponse {
    pub node: String,
    pub subscriber_jid: String,
    pub subid: Option<String>,
    pub allow: bool,
}

/// One item entry for Service Discovery items (`http://jabber.org/protocol/disco#items`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoItemWire {
    pub jid: String,
    pub node: Option<String>,
    pub name: Option<String>,
    pub published_item: bool,
}
