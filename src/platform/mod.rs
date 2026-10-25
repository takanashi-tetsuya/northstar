//! Process platform: configuration, the built-in XEP extension registry, the application error type and JID text
//! helpers. Worker supervision and connection actors live in `northstar-runtime`; logging, the metrics registry and
//! the delivery counters in `northstar-telemetry`.

pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod extensions;
pub(crate) mod jid_text;
