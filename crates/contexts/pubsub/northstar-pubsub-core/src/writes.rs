//! Generic PubSub write inputs.

use crate::{PubSubNode, PubSubNodeConfig, PubSubNodeId, PubSubSubscriptionOptions};

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
    pub node_id: PubSubNodeId,
    pub redirect: Option<&'a str>,
}

pub struct PubSubPurgeNodeWrite<'a> {
    pub requester: &'a str,
    pub node: &'a str,
    pub node_id: PubSubNodeId,
    pub observed_node: &'a PubSubNode,
}

pub struct PubSubConfigureNodeWrite<'a> {
    pub requester: &'a str,
    pub node: &'a PubSubNode,
    pub expected: &'a PubSubNodeConfig,
    pub config: &'a PubSubNodeConfig,
}

pub struct PubSubSetSubscriptionsWrite<'a> {
    pub requester: &'a str,
    pub node: &'a str,
    pub node_id: PubSubNodeId,
    pub changes: &'a [(String, String, Option<String>)],
}

pub struct PubSubSetAffiliationsWrite<'a> {
    pub requester: &'a str,
    pub node: &'a str,
    pub node_id: PubSubNodeId,
    pub changes: &'a [(String, String)],
}
