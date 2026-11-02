//! XMPP adapter of the message context: the client message stanza pipeline, from policy and abuse
//! admission through archiving, delivery, Carbons and personal retraction, and XEP-0215 external
//! service discovery.

#![forbid(unsafe_code)]

pub mod extdisco;
pub mod messaging;
pub mod ports;
mod retractions;
