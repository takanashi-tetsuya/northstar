//! Explicit wire-to-domain adapters.
//!
//! These types are intentionally separate from [`crate::generated`].  The
//! generated Protobuf modules are the only wire contract; adapter types are
//! local domain inputs/outputs and must never be serialized as an internal
//! RPC payload.

pub mod assertions;
pub mod common;
pub mod conversions;
pub mod delivery;
pub mod events;
pub mod identity;
pub mod ingress;
pub mod registry;
pub mod session;

pub use common::{
    ErrorContext, ErrorDetail, FieldViolation, IdempotencyKey, PageToken, RequestMetadata,
};
