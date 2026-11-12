//! The node's XMPP session: `ProtocolSession` with its protocol handlers, the advertised capabilities, MUC delivery
//! and the stage 4 harnesses. The native transports that carry the session are the `northstar-c2s` edge crate.

pub(crate) mod capabilities;
pub(crate) mod muc_delivery;
pub(crate) mod protocol;
#[cfg(test)]
pub(crate) mod stage4_auth_publication;
#[cfg(test)]
mod stage4_frame_capture;
#[cfg(test)]
pub(crate) mod stage4_native;
