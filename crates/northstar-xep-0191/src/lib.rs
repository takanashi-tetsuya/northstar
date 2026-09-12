#![forbid(unsafe_code)]

//! Capability-free XEP-0191 Blocking Command wire and policy support.
//!
//! Persistence, account authorization, cluster pushes, transport delivery and
//! presence sending remain application-service responsibilities.

pub mod builder;
pub mod constants;
pub mod error;
pub mod model;
pub mod policy;
pub mod wire;

pub use builder::{build_blocklist_result, build_payload};
pub use constants::{DESCRIPTOR, MAX_ITEMS, NAMESPACE, XEP_ID};
pub use error::BlockingError;
pub use model::{
    BlockPattern, BlockingCommand, BlockingEffects, BlockingMutation, BlockingSnapshot,
    PresencePeer, PresenceTransition, Subscription,
};
pub use policy::{plan_blocking_effects, presence_targets};
pub use wire::{parse_block, parse_blocklist, parse_blocklist_result, parse_iq, parse_unblock};
