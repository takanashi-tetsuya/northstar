//! XMPP adapter of the roster context: the RFC 6121 roster and presence, XEP-0016 privacy lists and XEP-0191
//! blocking, as handlers of client sessions.

#![forbid(unsafe_code)]

pub mod blocking;
pub mod privacy;

use northstar_roster_core::PresenceAccount;

/// The client session's identity, which every handler of this crate starts from.
pub trait SessionIdentity: Sync {
    /// The authenticated account, or `None` before authentication.
    fn session_account(&self) -> Option<PresenceAccount>;
    /// The server's local domain.
    fn session_local_domain(&self) -> &str;
}
