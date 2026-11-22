#![forbid(unsafe_code)]

//! PubSub commands, repository capabilities, publication policy and bounded
//! mutation admission. Database transactions stay in the PostgreSQL adapter.

pub mod repository;
pub use repository::*;
pub mod item_snapshot;
pub use item_snapshot::*;
mod pep_snapshot;
pub use pep_snapshot::*;
pub mod private_storage;
pub mod profile;
pub mod service;
pub mod subscription_cleanup;
pub use service::PubSubService;
mod discovery_snapshot;
pub use discovery_snapshot::*;
mod list_page;
pub use list_page::{page_pubsub_list, PubSubListPage, PubSubListPageError, PubSubListPageQuery};
mod root_discovery;
pub use root_discovery::{discover_roots, PubSubRootDiscoQuery, PubSubRootDiscoResult};
mod publish_policy;
pub use publish_policy::{existing_node_publish_admission_outcome, publish_validation_outcome};

mod admission;
mod admission_key;
mod commands;
pub use admission::*;
pub use admission_key::*;
pub use commands::*;

#[cfg(test)]
use northstar_pubsub_core::{
    PepDeleteNodeWrite, PepQuotas, PepRetractWrite, PubSubSubscriptionOptions,
    SubscriptionAuthorizationOutcome,
};
#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
mod tests;
