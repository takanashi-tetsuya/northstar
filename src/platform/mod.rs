//! Process configuration. Worker supervision and connection actors live in `northstar-runtime`; logging, the
//! metrics registry and the delivery counters in `northstar-telemetry`; security mechanisms in
//! `northstar-security`; the XEP catalog in `northstar-xep-catalog`.

pub(crate) mod config;
