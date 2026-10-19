//! Process platform: configuration, the application error type, logging, the metrics registry and worker and connection-actor supervision.

pub(crate) mod config;
pub(crate) mod connection_actors;
pub(crate) mod error;
pub(crate) mod logging;
pub(crate) mod metrics;
pub(crate) mod workers;
