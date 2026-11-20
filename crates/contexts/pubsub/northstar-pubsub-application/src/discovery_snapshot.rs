//! Authorized service discovery and self lists, including redirects on a node miss.

use crate::{PubSubCollectionDiscoSnapshot, PubSubLeafDiscoSnapshot};
use anyhow::Result;
use northstar_pubsub_core::{
    PubSubAffiliation, PubSubNode, PubSubNodeMetadata, PubSubSubscription,
};
use std::future::Future;

pub struct PubSubNodeInfoQuery<'a> {
    pub node: &'a str,
    pub requester: &'a str,
}

#[derive(Debug)]
pub enum PubSubNodeInfo {
    Missing {
        redirect: Option<String>,
    },
    Forbidden,
    Info {
        node: Box<PubSubNode>,
        metadata: PubSubNodeMetadata,
    },
}

pub struct PubSubNodeItemsQuery<'a> {
    pub node: &'a str,
    pub requester: &'a str,
}

#[derive(Debug)]
pub enum PubSubNodeItems {
    Missing { redirect: Option<String> },
    Forbidden,
    UnsupportedKind,
    Leaf(PubSubLeafDiscoSnapshot),
    Collection(PubSubCollectionDiscoSnapshot),
}

pub struct PubSubSelfListQuery<'a> {
    pub node: Option<&'a str>,
    pub requester: &'a str,
}

#[derive(Debug)]
pub enum PubSubSelfList<T> {
    Missing { redirect: Option<String> },
    List(Vec<T>),
}

/// Resolve node identity, access and the requested projection on one read snapshot.
pub trait PubSubDiscoverySnapshotRepository: Send + Sync {
    fn node_info(
        &self,
        query: &PubSubNodeInfoQuery<'_>,
    ) -> impl Future<Output = Result<PubSubNodeInfo>> + Send;

    fn node_items(
        &self,
        query: &PubSubNodeItemsQuery<'_>,
    ) -> impl Future<Output = Result<PubSubNodeItems>> + Send;

    /// The unfiltered list always returns `List`.
    fn self_subscriptions(
        &self,
        query: &PubSubSelfListQuery<'_>,
    ) -> impl Future<Output = Result<PubSubSelfList<PubSubSubscription>>> + Send;

    /// The unfiltered list always returns `List`.
    fn self_affiliations(
        &self,
        query: &PubSubSelfListQuery<'_>,
    ) -> impl Future<Output = Result<PubSubSelfList<PubSubAffiliation>>> + Send;
}
