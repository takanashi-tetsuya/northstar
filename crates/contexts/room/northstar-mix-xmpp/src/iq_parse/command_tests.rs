use super::*;

#[test]
fn invitation_get_is_a_command_with_a_canonical_invitee() {
    let payload =
        "<invite xmlns='urn:xmpp:mix:misc:0'><invitee>Guest@Remote.TEST</invitee></invite>";
    let request = parse_iq(&format!(
        "<iq type='get' id='invite' to='room@mix.example.test'>{payload}</iq>"
    ))
    .unwrap()
    .unwrap();
    assert!(crate::federation::federated_mix_iq_is_mutation(&request));
    let IqOperation::IssueMixInvitation {
        invitee: Some(invitee),
    } = request.operation
    else {
        panic!("expected a typed invitation command");
    };
    assert_eq!(invitee.as_str(), "guest@remote.test");
    assert!(
        parse_iq(&format!("<iq type='set' id='invite'>{payload}</iq>"))
            .unwrap()
            .is_none()
    );
}
