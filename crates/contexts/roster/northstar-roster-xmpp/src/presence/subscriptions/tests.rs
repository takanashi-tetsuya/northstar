use super::*;
use roxmltree::Document;

#[test]
fn subscription_policy_denials_preserve_wire_conditions() {
    let request = Document::parse("<presence type='subscribe' id='test'/>").unwrap();
    for (reason, error_type, condition, blocked) in [
        (
            PresencePolicyDenial::Blocking,
            "cancel",
            "not-acceptable",
            true,
        ),
        (
            PresencePolicyDenial::Privacy,
            "cancel",
            "service-unavailable",
            false,
        ),
    ] {
        let reply = subscription_policy_error(request.root_element(), reason);
        let document = Document::parse(&reply).unwrap();
        let root = document.root_element();
        let error = root
            .children()
            .find(|child| child.has_tag_name("error"))
            .unwrap();
        assert_eq!(root.attribute("id"), Some("test"));
        assert_eq!(error.attribute("type"), Some(error_type));
        assert!(error.children().any(|child| {
            child.has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", condition))
        }));
        assert_eq!(
            error
                .children()
                .any(|child| child.has_tag_name(("urn:xmpp:blocking:errors", "blocked"))),
            blocked,
        );
    }
}
