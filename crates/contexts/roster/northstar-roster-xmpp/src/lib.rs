//! XMPP adapter of the roster context: the RFC 6121 roster and presence, XEP-0016 privacy lists and XEP-0191
//! blocking, as handlers of client sessions.

#![forbid(unsafe_code)]

mod avatar_presence;
pub mod blocking;
pub mod fanout;
pub mod federated_presence;
pub mod presence;
pub mod presence_delivery;
pub mod privacy;
mod protocol_session;
pub mod roster;
mod roster_journal;
pub mod roster_push;
mod session_host;
mod subscription_retry;

pub use self::avatar_presence::AvatarPresenceGate;
pub use self::protocol_session::PresenceHandlers;
pub use self::protocol_session::{BlockingHandlers, PrivacyHandlers, RosterHandlers};
pub use self::roster_journal::RosterJournalReader;
pub use self::session_host::federated_presence::{
    FederatedPresenceEffect, FederatedPresenceHandoff, FederatedPresenceOwnerHost,
};
pub use self::session_host::{
    FederatedPresenceHost, PostAcceptFailureTelemetry, PresenceDeliveryHost, PresenceRouting,
    RosterSessionHost,
};
pub use self::subscription_retry::SubscriptionRetryWake;

use northstar_roster_core::PresenceAccount;

pub mod exact_presence;

/// The client session's identity, which every handler of this crate starts from.
pub trait SessionIdentity: Sync {
    /// The authenticated account, or `None` before authentication.
    fn session_account(&self) -> Option<PresenceAccount>;
    /// The server's local domain.
    fn session_local_domain(&self) -> &str;
    /// The roster actor, or `None` until the session is authenticated and bound.
    fn roster_actor(&self) -> Option<northstar_roster_core::RosterActor>;
    /// The source of time and protocol IDs for roster effects.
    fn roster_events(&self) -> &dyn northstar_roster_core::RosterEventSource;
}
