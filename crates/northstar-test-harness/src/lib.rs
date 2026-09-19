pub mod activation;
pub mod database;
pub mod diagnostics;
pub mod listener;
pub mod process;
pub mod readiness;

pub use activation::{channel, Activation, Readiness};
pub use database::IsolatedSchema;
pub use diagnostics::{is_port_listening, wait_for_port, wait_for_port_closed};
pub use listener::{PortRange, PreboundListener};
pub use process::ManagedProcess;
pub use readiness::{ReadinessRecord, ReadinessTranscript};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn activation_channel_delivers_listener_address() {
        let (activation, readiness) = channel("test-service");
        let listener = PreboundListener::bind_ephemeral().expect("bind ephemeral failed");
        let address = listener.local_addr();
        tokio::task::spawn_blocking(move || activation.announce(address))
            .await
            .expect("activation announcement task failed")
            .expect("activation receiver should be available");
        assert_eq!(
            readiness
                .wait_for(std::time::Duration::from_secs(1))
                .await
                .expect("readiness should arrive"),
            address,
            "readiness channel should receive listener address"
        );
    }

    #[test]
    fn prebound_listener_allocates_port() {
        let listener = PreboundListener::bind_ephemeral().expect("bind ephemeral failed");
        let port = listener.port();
        assert!(port > 0);
        let std_listener = listener.into_std();
        assert_eq!(std_listener.local_addr().unwrap().port(), port);
    }

    #[test]
    fn port_range_allocation() {
        let range = PortRange::new(35000, 35050);
        let listeners = range
            .allocate_listeners(3)
            .expect("range allocation failed");
        assert_eq!(listeners.len(), 3);
        assert_ne!(listeners[0].port(), listeners[1].port());
        assert_ne!(listeners[1].port(), listeners[2].port());
        for l in &listeners {
            assert!(l.port() >= 35000 && l.port() <= 35050);
        }
    }

    #[test]
    fn isolated_schema_lifecycle_sql() {
        let schema = IsolatedSchema::new("test_suite");
        assert!(schema.name().starts_with("test_suite_"));
        assert!(schema.create_sql().contains(schema.name()));
        assert!(schema.drop_cascade_sql().contains("DROP SCHEMA IF EXISTS"));
    }
}
