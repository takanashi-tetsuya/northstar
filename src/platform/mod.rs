//! Process platform: configuration, the built-in XEP extension registry, the delivery-queue counters, the application
//! error type, JID text helpers, logging, the metrics registry and worker and connection-actor supervision.

pub(crate) mod config;
pub(crate) mod connection_actors;
pub(crate) mod delivery_counters;
pub(crate) mod error;
pub(crate) mod extensions;
pub(crate) mod jid_text;
pub(crate) mod logging;
pub(crate) mod metrics;
pub(crate) mod workers;
