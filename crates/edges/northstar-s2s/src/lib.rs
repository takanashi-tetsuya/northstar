//! Server-to-server pieces of Northstar that need nothing from the node: federation endpoint discovery (SRV,
//! XEP-0368 and XEP-0487 host-meta), TLS and certificate identity for XMPP servers, bounded stream reads and writes,
//! and the registry through which a peer resumes its stream (XEP-0198). The connection actors that use them are
//! still in the composition root.

#![forbid(unsafe_code)]

pub mod dns;
pub mod resume;
pub mod tls;
pub mod util;
