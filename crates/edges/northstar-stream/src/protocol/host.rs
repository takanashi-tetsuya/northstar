//! What a protocol session needs from the node it runs in.

mod account;
mod caps;
mod dispatch;
mod identity;
mod lifecycle;
mod message_effects;
mod mix_ack;
mod muc;
mod presence_policy;
mod pubsub_effects;
mod routes;
mod sm;
mod telemetry;

pub use self::account::SessionAccountHost;
pub use self::caps::SessionCapsHost;
pub use self::dispatch::SessionDispatchHost;
pub use self::identity::SessionIdentityHost;
pub use self::lifecycle::SessionLifecycleHost;
pub use self::message_effects::SessionMessageEffectsHost;
pub use self::mix_ack::SessionMixAckHost;
pub use self::muc::SessionMucHost;
pub use self::presence_policy::SessionPresencePolicyHost;
pub use self::pubsub_effects::SessionPubSubEffectsHost;
pub use self::routes::SessionRoutesHost;
pub use self::sm::SessionSmHost;
pub use self::telemetry::SessionTelemetryHost;

/// The aggregate host a [`super::ProtocolSession`] needs.
pub trait SessionHost:
    SessionIdentityHost
    + SessionAccountHost
    + SessionRoutesHost
    + SessionCapsHost
    + SessionSmHost
    + SessionMucHost
    + SessionPresencePolicyHost
    + SessionMessageEffectsHost
    + SessionMixAckHost
    + SessionPubSubEffectsHost
    + SessionDispatchHost
    + SessionLifecycleHost
    + SessionTelemetryHost
    + Sized
    + Send
    + Sync
    + 'static
{
}

impl<T> SessionHost for T where
    T: SessionIdentityHost
        + SessionAccountHost
        + SessionRoutesHost
        + SessionCapsHost
        + SessionSmHost
        + SessionMucHost
        + SessionPresencePolicyHost
        + SessionMessageEffectsHost
        + SessionMixAckHost
        + SessionPubSubEffectsHost
        + SessionDispatchHost
        + SessionLifecycleHost
        + SessionTelemetryHost
        + Sized
        + Send
        + Sync
        + 'static
{
}
