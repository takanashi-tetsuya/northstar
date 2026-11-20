//! Authorized service item and subscription-options snapshots.

use anyhow::Result;
use northstar_pubsub_core::{CollectionVisibleItem, PubSubItem, PubSubSubscription};
use northstar_xep_0060::PubSubError;
use uuid::Uuid;

pub struct PubSubItemQuery<'a> {
    pub node: &'a str,
    /// The requester's canonical bare JID.
    pub requester: &'a str,
    pub echoed_subid: Option<&'a str>,
    /// A valid leaf selection, if the request can be used with a persistent leaf.
    pub leaf: Option<PubSubLeafItemSelection<'a>>,
    pub collection: PubSubCollectionItemSelection,
}

#[derive(Clone, Copy)]
pub struct PubSubLeafItemSelection<'a> {
    /// An empty slice selects items by recency. An explicit ID list can also be capped.
    pub item_ids: &'a [String],
    pub max_items: Option<i64>,
}

#[derive(Clone, Copy)]
pub enum PubSubCollectionItemSelection {
    Items { max_items: i64, max_xml_bytes: i64 },
    BadRequest,
    RsmUnsupported,
}

#[derive(Debug)]
pub enum PubSubItemRead {
    Missing {
        redirect: Option<String>,
    },
    Denied(PubSubError),
    NonPersistent,
    BadRequest,
    CollectionRsmUnsupported,
    Leaf {
        max_items: i32,
        items: Vec<PubSubItem>,
    },
    Collection {
        items: Vec<CollectionVisibleItem>,
    },
}

pub struct PubSubOptionsQuery<'a> {
    pub node: &'a str,
    /// The exact subscriber JID, which can be bare or full.
    pub subscriber_jid: &'a str,
    pub echoed_subid: Option<&'a str>,
}

#[derive(Debug)]
pub struct PubSubOptionsNode {
    pub id: Uuid,
    pub node_type: String,
    pub payload_type: Option<String>,
}

#[derive(Debug)]
pub enum PubSubOptionsRead {
    Missing {
        redirect: Option<String>,
    },
    NotSubscribed,
    InvalidSubid,
    Ready {
        node: Box<PubSubOptionsNode>,
        subscription: PubSubSubscription,
    },
}

/// Select authority and the requested data from the same read-only snapshot.
pub trait PubSubItemSnapshotRepository: Send + Sync {
    fn item_read(
        &self,
        query: &PubSubItemQuery<'_>,
    ) -> impl std::future::Future<Output = Result<PubSubItemRead>> + Send;

    fn subscription_options_read(
        &self,
        query: &PubSubOptionsQuery<'_>,
    ) -> impl std::future::Future<Output = Result<PubSubOptionsRead>> + Send;
}
