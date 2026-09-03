#![forbid(unsafe_code)]

//! Capability-free XEP-0359 Unique and Stable Stanza IDs support.
//!
//! The crate owns bounded wire validation, safe fragment construction and pure
//! identity/authority decisions. It does not generate UUIDs, authenticate
//! routes, query discovery, store replay identities, mutate archives or route
//! messages.

pub mod builder;
pub mod constants;
pub mod error;
pub mod model;
pub mod policy;
pub mod wire;

pub use builder::{build_origin_id, build_referenced_stanza, build_stanza_id};
pub use constants::{DESCRIPTOR, MAX_ID_BYTES, MAX_ID_ELEMENTS, NAMESPACE, XEP_ID};
pub use error::SidError;
pub use model::{DeduplicationKey, MessageIds, OriginId, ReferencedStanza, StableId, StanzaId};
pub use policy::{
    authoritative_deduplication_key, origin_deduplication_key, plan_authority_update,
    stanza_id_trust, AuthorityUpdate, ReferenceTrust,
};
pub use wire::{
    parse_message, parse_origin_id, parse_referenced_stanza, parse_stanza_id, validate_id,
};
