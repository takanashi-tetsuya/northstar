//! Compatibility facade for Northstar's capability-free authentication core.
//!
//! Password hashing, SCRAM/SASL state machines, channel binding and FAST
//! cryptography have one implementation in `northstar-auth-core`. Keeping
//! this facade lets application call sites move independently without
//! retaining a second security-sensitive implementation.

pub use northstar_auth_core::*;
