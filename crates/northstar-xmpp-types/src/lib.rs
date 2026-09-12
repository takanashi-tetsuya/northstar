//! RFC 7622 JID parsing, preparation, and canonical comparison for Northstar.
//!
//! Component separators are located before applying any Unicode mapping, as
//! required by RFC 7622. Localparts and resourceparts use the maintained
//! PRECIS profiles from RFC 8265; domain names use IDNA/UTS #46 processing.

#![forbid(unsafe_code)]

pub mod jid;

pub use jid::{
    canonical_bare_key, canonical_session_key, canonicalize, canonicalize_bare, domain_to_ascii,
    jid_scope_matches, prepare_domainpart, prepare_localpart, prepare_resourcepart, CanonicalJid,
};
