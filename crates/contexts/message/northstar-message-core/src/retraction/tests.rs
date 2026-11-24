use super::{personal_retraction_command, retraction_target, InvalidPersonalRetraction};
use roxmltree::Document;

#[test]
fn explicit_no_store_refuses_a_valid_personal_retraction_even_with_store() {
    for namespace in ["jabber:client", "jabber:server", "jabber:component:accept"] {
        for other_hint in ["", "<store xmlns='urn:xmpp:hints'/>"] {
            let stanza = format!(
                "<message xmlns='{namespace}' id='action'>\
                 <retract xmlns='urn:xmpp:message-retract:1' id='original'/>\
                 <no-store xmlns='urn:xmpp:hints'/>{other_hint}</message>"
            );
            let document = Document::parse(&stanza).unwrap();
            let root = document.root_element();
            assert_eq!(
                personal_retraction_command(root),
                Err(InvalidPersonalRetraction::NoStore)
            );
            assert_eq!(
                retraction_target(root),
                Err(InvalidPersonalRetraction::NoStore)
            );
        }
    }
}
