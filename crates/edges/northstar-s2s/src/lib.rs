//! The server-to-server transport of Northstar: federation endpoint discovery (SRV, XEP-0368 and XEP-0487
//! host-meta), TLS and certificate identity for XMPP servers, bounded stream reads and writes, stream management and
//! resumption (XEP-0198), the outbound connection actors that drain the federation outbox, inbound stream
//! negotiation and sessions, and external components (XEP-0114 and XEP-0225). It reaches the node only through the
//! ports in [`host`]; the node routes the stanzas a peer sends.

#![forbid(unsafe_code)]

pub mod components;
pub mod dns;
pub mod host;
pub mod inbound;
pub mod outbound;
pub mod outbox;
pub mod resume;
mod sm;
pub mod tls;
pub mod util;
