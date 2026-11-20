//! PEP queries that return authority and their projection from one snapshot.

use anyhow::Result;
use northstar_pubsub_core::{PepAccessDenial, PepNodeConfig, PepSubscription, PubSubAccount};

#[derive(Clone, Copy, Debug)]
pub enum PepRequester<'a> {
    Jid(&'a str),
    LocalAnonymous,
}

#[derive(Debug)]
pub struct PepItemSelection {
    /// An empty list selects the latest items.
    pub item_ids: Vec<String>,
    pub max_items: i64,
}

pub struct PepItemQuery<'a> {
    pub owner_username: &'a str,
    pub requester_jid: &'a str,
    pub node: &'a str,
    /// Omit the selection to check access alone, preserving error precedence
    /// when an adapter has rejected the requested IDs or limit.
    pub selection: Option<PepItemSelection>,
}

#[derive(Debug)]
pub enum PepItemRead {
    OwnerMissing,
    NodeMissing,
    Denied(PepAccessDenial),
    Items {
        config: PepNodeConfig,
        items: Vec<(String, String)>,
    },
}

pub struct PepNodeQuery<'a> {
    pub owner_username: &'a str,
    pub requester: PepRequester<'a>,
    pub node: &'a str,
}

#[derive(Debug)]
pub enum PepNodeInfoRead {
    OwnerMissing,
    NodeMissing,
    Denied(PepAccessDenial),
    Info { config: PepNodeConfig },
}

#[derive(Debug, Eq, PartialEq)]
pub enum PepNodeItemsRead {
    OwnerMissing,
    NodeMissing,
    Denied,
    Visible,
}

pub struct PepAccountQuery<'a> {
    pub owner_username: &'a str,
    pub requester: PepRequester<'a>,
}

#[derive(Debug)]
pub enum PepAccountItemsRead {
    OwnerMissing,
    Nodes {
        owner_jid: String,
        nodes: Vec<String>,
    },
}

pub struct PepOwnerQuery<'a> {
    pub owner: &'a PubSubAccount,
    pub node: &'a str,
}

#[derive(Debug)]
pub enum PepOwnerSubscriptionsRead {
    NodeMissing,
    Subscribers(Vec<PepSubscription>),
}

pub trait PepSnapshotRepository: Send + Sync {
    fn pep_items_read(
        &self,
        query: &PepItemQuery<'_>,
    ) -> impl std::future::Future<Output = Result<PepItemRead>> + Send;

    fn pep_node_info(
        &self,
        query: &PepNodeQuery<'_>,
    ) -> impl std::future::Future<Output = Result<PepNodeInfoRead>> + Send;

    fn pep_node_items(
        &self,
        query: &PepNodeQuery<'_>,
    ) -> impl std::future::Future<Output = Result<PepNodeItemsRead>> + Send;

    fn pep_account_items(
        &self,
        query: &PepAccountQuery<'_>,
    ) -> impl std::future::Future<Output = Result<PepAccountItemsRead>> + Send;

    fn pep_owner_subscriptions(
        &self,
        query: &PepOwnerQuery<'_>,
    ) -> impl std::future::Future<Output = Result<PepOwnerSubscriptionsRead>> + Send;
}
