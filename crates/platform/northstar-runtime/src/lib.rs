//! Worker supervision, shutdown and connection-actor admission for the Northstar runtime.

#![forbid(unsafe_code)]

pub mod connection_actors;
pub mod durable_outbox;
pub mod listeners;
pub mod process_shutdown;
pub mod service_tasks;
pub mod test_activation;
pub mod workers;
