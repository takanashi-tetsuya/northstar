use super::{allows_configured_component_target, s2s_stream_address_error};

#[test]
fn only_messages_to_configured_components_can_use_the_component_target_exception() {
    for (kind, source, target, expected) in [
        ("message", "remote.test", "component.test", true),
        ("message", "spoofed.test", "component.test", false),
        ("message", "remote.test", "unconfigured.test", false),
        ("presence", "remote.test", "component.test", false),
        ("iq", "remote.test", "component.test", false),
    ] {
        let raw = format!(
            "<{kind} xmlns='jabber:server' from='alice@{source}/phone' to='bob@{target}'/>"
        );
        let error = s2s_stream_address_error(&raw, "remote.test", "local.test").unwrap();
        assert_eq!(
            allows_configured_component_target(&raw, error, |domain| domain == "component.test"),
            expected,
            "{raw}",
        );
    }
}
