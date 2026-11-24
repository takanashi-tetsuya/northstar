use super::{policy_error, DirectPolicyDenial};
use northstar_stream::transport::Action;

#[test]
fn policy_denials_keep_the_existing_c2s_stanza_errors() {
    let request = roxmltree::Document::parse("<message to='bob@example.test'/>").unwrap();
    for (denial, kind, condition, blocked) in [
        (
            DirectPolicyDenial::ActorUnavailable,
            "cancel",
            "service-unavailable",
            false,
        ),
        (
            DirectPolicyDenial::OutboundBlock,
            "cancel",
            "not-acceptable",
            true,
        ),
        (
            DirectPolicyDenial::OutboundPrivacy,
            "cancel",
            "service-unavailable",
            false,
        ),
        (
            DirectPolicyDenial::RecipientBlock,
            "cancel",
            "service-unavailable",
            false,
        ),
        (
            DirectPolicyDenial::RecipientPrivacy,
            "cancel",
            "service-unavailable",
            false,
        ),
        (
            DirectPolicyDenial::DegradedSpool,
            "wait",
            "service-unavailable",
            false,
        ),
    ] {
        let Action::Send(stanza) = policy_error(request.root_element(), denial) else {
            panic!("expected a stanza error for {denial:?}");
        };
        let response = roxmltree::Document::parse(&stanza).unwrap();
        let error = response
            .root_element()
            .children()
            .find(|child| child.has_tag_name("error"))
            .unwrap();
        assert_eq!(error.attribute("type"), Some(kind));
        assert!(error
            .children()
            .any(|child| child.has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", condition))));
        assert_eq!(
            error
                .children()
                .any(|child| child.has_tag_name(("urn:xmpp:blocking:errors", "blocked"))),
            blocked
        );
    }
}
