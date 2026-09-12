//! Compatibility facade for Northstar's canonical XMPP identity types.
//!
//! All RFC 7622, PRECIS and IDNA behavior is owned by the independently
//! compiled `northstar-xmpp-types` foundation crate. Keeping this module as a
//! re-export lets existing application adapters migrate without maintaining a
//! second identity implementation.

pub use northstar_xmpp_types::jid::*;
