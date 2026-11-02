//! XMPP adapter of the message context: the client message stanza pipeline, from policy and abuse
//! admission through archiving, delivery, Carbons and personal retraction.

#![forbid(unsafe_code)]

pub mod messaging;
pub mod ports;
mod retractions;
