use super::{abuse_stanza_error, apply_decision, MessageAdmissionStart};
use northstar_abuse_policy::{GuardError, WorkRequirement};
use northstar_stream::transport::Action;
use roxmltree::Document;
use std::cell::Cell;

#[test]
fn rated_refusals_drop_errors_without_changing_non_error_pow_replies() {
    let requirement = WorkRequirement {
        action: "message".into(),
        step: 1,
        work_factor: 100,
        max_work_factor: 100,
        hard_wait_seconds: 0,
        retry_after_seconds: 5,
        cooldown_seconds: 5,
        approximate_max_device_seconds: 1,
        notice: "test".into(),
    };
    for kind in ["error", "chat"] {
        let error = if kind == "error" {
            "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
        } else {
            ""
        };
        let raw = format!(
            "<message xmlns='jabber:client' from='alice@example.test/phone' to='bob@example.test' type='{kind}' id='test'><body>rated</body>{error}</message>"
        );
        let document = Document::parse(&raw).unwrap();
        let root = document.root_element();
        assert!(northstar_xml_builder::message_policy::is_abuse_rated_message(root));
        for decision in [
            MessageAdmissionStart::InProgress {
                requirement: requirement.clone(),
            },
            MessageAdmissionStart::Denied(GuardError::Required(requirement.clone())),
        ] {
            let limited = Cell::new(false);
            let mut lease = None;
            let action = apply_decision(root, decision, &mut lease, || limited.set(true));
            assert!(limited.get());
            assert!(lease.is_none());
            match (kind, action) {
                ("error", Some(Action::None)) => {}
                ("chat", Some(Action::Send(reply))) => {
                    assert_eq!(reply, abuse_stanza_error(root, &requirement));
                }
                _ => panic!("unexpected rated refusal for {kind}"),
            }
        }
    }
}
